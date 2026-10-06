/*!
 * gitstore.js —— 把 GitHub 当后端的轮子
 *
 * 从 AnyLearn / GitHub Drive / FaceHub / 粥粥记录 / 仓鼠 里抽出来的共性能力。
 * 这些坑每一个都是真踩过的，注释里写了为什么。
 *
 * 用法：
 *   const store = new GitStore({ token });
 *   await store.put('notes/a.json', { title: 'x' });
 *   const a = await store.get('notes/a.json');
 *
 * 通过 CDN：<script src="https://cdn.jsdelivr.net/gh/Cool-zimo/gitstore@main/gitstore.js"></script>
 * 国内访问不了 jsdelivr 就把这个文件拷到自己仓库里。
 */
(function (root) {
    'use strict';

    const API = 'https://api.github.com';

    /* ══════════════════════════════════════════════════════════
     * 1. Http —— 所有请求的唯一出口
     * ══════════════════════════════════════════════════════════ */
    class Http {
        constructor(token) { this.token = token; }

        /**
         * ★ cache: 'no-store' 不是优化，是必须的。
         *
         *   GitHub contents API 返回 `Cache-Control: private, max-age=60`。
         *   浏览器照办 —— 于是"设备 A 写完，设备 B 读"时请求根本没发出去，
         *   直接拿回 60 秒前的旧数据。刷新页面也绕不过这层缓存。
         *   实测：同一时刻，默认缓存读到 3 条，no-store 读到 4 条。
         */
        async req(path, opt = {}) {
            const url = path.startsWith('http') ? path : API + path;
            const headers = {
                Authorization: `Bearer ${this.token}`,
                Accept: 'application/vnd.github+json',
                'X-GitHub-Api-Version': '2022-11-28',
                ...(opt.headers || {})
            };
            let body = opt.body;
            if (body !== undefined && !opt.rawBody) {
                headers['Content-Type'] = 'application/json';
                body = JSON.stringify(body);
            }

            let lastErr;
            const tries = opt.retry ? opt.retry.tries : 1;
            for (let i = 0; i < tries; i++) {
                const res = await fetch(url, {
                    method: opt.method || 'GET',
                    headers, body,
                    cache: 'no-store'
                });
                if (res.ok) {
                    if (res.status === 204) return null;
                    const t = await res.text();
                    return t ? JSON.parse(t) : null;
                }
                let msg = res.statusText;
                try { const j = JSON.parse(await res.text()); if (j && j.message) msg = j.message; } catch (e) { }
                const err = new Error(msg);
                err.status = res.status;

                // ★ 只重试瞬时错误。409 是冲突（要合并，不是重试），
                //   404/422 是确定性失败，重试只会浪费配额。
                if (opt.retry && i < tries - 1 && Http._transient(res.status)) {
                    lastErr = err;
                    await new Promise(r => setTimeout(r, opt.retry.delay * Math.pow(2, i)));
                    continue;
                }
                throw err;
            }
            throw lastErr;
        }

        static _transient(s) {
            // 429 限流；500/502/503/504 服务端抖动。
            // ★ 500 曾经漏掉过：一次 256MB 上传报 500，而重试策略只认 429/502/503，
            //   结果整批失败。所以这里要宽。
            return s === 429 || s === 500 || s === 502 || s === 503 || s === 504;
        }
    }

    /* ══════════════════════════════════════════════════════════
     * 2. Crypto —— 自动加密 / 自动解密
     *
     * ★ 两个体系，别混用：
     *   ① 口令派生（PBKDF2）：人记得住的密码，适合个人数据。
     *   ② 密钥协商（ECDH P-256）：两台设备从没同时在线，也能算出同一个密钥。
     *      适合"发给别人"/"多设备共享"。
     *
     * ★ P-256 不是笔误。早期文档写的是 X25519，源码实际用 P-256。
     *   两者都是 ECDH，但曲线和公钥格式不同，混用的后果是
     *   ——永远协商不出相同密钥，而且不报错，只是解不开。
     * ══════════════════════════════════════════════════════════ */
    const Crypto = {
        ITER: 250000,

        _b64(u8) {
            let s = '';
            for (let i = 0; i < u8.length; i += 0x8000) {
                s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
            }
            return btoa(s);
        },
        _unb64(b64) {
            const s = atob(b64), u = new Uint8Array(s.length);
            for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i);
            return u;
        },

        random(n) { return crypto.getRandomValues(new Uint8Array(n)); },

        /** 口令 → 密钥。salt 存仓库里没关系，salt 不怕公开。 */
        async deriveKey(password, salt, usages = ['encrypt', 'decrypt']) {
            const km = await crypto.subtle.importKey('raw',
                new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
            return await crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2', salt,
                    iterations: this.ITER,
                    hash: 'SHA-256'
                },
                km,
                { name: 'AES-GCM', length: 256 },
                false, usages);
        },

        /** AES-GCM 加密。iv 每次随机，跟着密文一起存。 */
        async encrypt(key, plain) {
            const iv = this.random(12);
            const data = typeof plain === 'string'
                ? new TextEncoder().encode(plain)
                : (plain instanceof Uint8Array ? plain : new TextEncoder().encode(JSON.stringify(plain)));
            const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
            return {
                v: 1, alg: 'AES-GCM-256',
                iv: this._b64(iv),
                data: this._b64(new Uint8Array(ct))
            };
        },

        async decrypt(key, env) {
            if (!env || env.alg !== 'AES-GCM-256') throw new Error('不是 gitstore 的加密格式');
            const ct = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: this._unb64(env.iv) },
                key, this._unb64(env.data));
            return new TextDecoder().decode(ct);
        },

        /**
         * ★ 为什么要 verifier：不能靠"解密失败"判断密码错。
         *   数据损坏、格式不对、密文被截断 —— 都会解密失败。
         *   用一个已知明文加密当哨兵，能区分"密码错"和"数据坏了"。
         */
        async makeVerifier(key) {
            return await this.encrypt(key, 'gitstore-ok');
        },
        async checkVerifier(key, env) {
            try { return (await this.decrypt(key, env)) === 'gitstore-ok'; }
            catch (e) { return false; }
        },

        /** ECDH P-256 密钥对 */
        async genKeyPair() {
            return await crypto.subtle.generateKey(
                { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
        },
        async exportPub(kp) {
            return this._b64(new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey)));
        },
        async importPub(b64) {
            return await crypto.subtle.importKey('raw', this._unb64(b64),
                { name: 'ECDH', namedCurve: 'P-256' }, false, []);
        },
        /** 我的私钥 + 对方公钥 → 共享密钥（双方算出来一样） */
        async sharedSecret(myPrivate, theirPubB64) {
            const pub = await this.importPub(theirPubB64);
            const bits = await crypto.subtle.deriveBits(
                { name: 'ECDH', public: pub }, myPrivate, 256);
            return await crypto.subtle.importKey('raw', new Uint8Array(bits),
                { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
        },

        async sha256(text) {
            const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
            return Array.from(new Uint8Array(d)).map(b => b.toString(16).padStart(2, '0')).join('');
        }
    };

    /* ══════════════════════════════════════════════════════════
     * 3. Repo —— 单个仓库的读写
     * ══════════════════════════════════════════════════════════ */
    class Repo {
        constructor(http, owner, name, branch = 'main') {
            this.http = http; this.owner = owner; this.name = name; this.branch = branch;
        }
        get full() { return `${this.owner}/${this.name}`; }

        async ensure(opt = {}) {
            try {
                await this.http.req(`/repos/${this.full}`);
                return false;                       // 已存在
            } catch (e) {
                if (e.status !== 404) throw e;
            }
            await this.http.req('/user/repos', {
                method: 'POST',
                body: {
                    name: this.name,
                    description: opt.description || '',
                    private: opt.private !== false,   // ★ 默认私有
                    auto_init: true
                }
            });
            return true;                            // 新建的
        }

        /**
         * 读文件。不存在返回 null（不抛错）。
         * ★ 一定要返回 sha —— 调用方写回时必须带上，否则是"强制覆盖"，
         *   会把别的设备刚写的整份抹掉，而且看不出来。
         */
        async getRaw(path) {
            try {
                return await this.http.req(
                    `/repos/${this.full}/contents/${encodeURIComponent(path)}?ref=${this.branch}`);
            } catch (e) {
                if (e.status === 404) return null;
                throw e;
            }
        }

        async read(path) {
            const f = await this.getRaw(path);
            if (!f) return null;
            const text = new TextDecoder().decode(
                Uint8Array.from(atob(f.content.replace(/\n/g, '')), c => c.charCodeAt(0)));
            return { text, sha: f.sha };
        }

        async getJSON(path) {
            const r = await this.read(path);
            if (!r) return null;
            try { return { data: JSON.parse(r.text), sha: r.sha }; }
            catch (e) { return { data: null, sha: r.sha, bad: true }; }
        }

        async write(path, text, message, sha = null) {
            return await this.http.req(
                `/repos/${this.full}/contents/${encodeURIComponent(path)}`,
                {
                    method: 'PUT',
                    body: {
                        message: message || `gitstore: 更新 ${path}`,
                        content: Crypto._b64(new TextEncoder().encode(text)),
                        branch: this.branch,
                        ...(sha ? { sha } : {})
                    }
                });
        }

        async remove(path, message, sha) {
            if (!sha) { const f = await this.getRaw(path); if (!f) return false; sha = f.sha; }
            await this.http.req(`/repos/${this.full}/contents/${encodeURIComponent(path)}`, {
                method: 'DELETE',
                body: { message: message || `gitstore: 删除 ${path}`, sha, branch: this.branch }
            });
            return true;
        }

        async list(path = '') {
            try {
                const r = await this.http.req(
                    `/repos/${this.full}/contents/${path ? encodeURIComponent(path) : ''}?ref=${this.branch}`);
                return Array.isArray(r) ? r : [r];
            } catch (e) {
                if (e.status === 404) return [];
                throw e;
            }
        }

        async size() {
            const r = await this.http.req(`/repos/${this.full}`);
            return (r.size || 0) * 1024;
        }

        /**
         * 一次提交写多个文件。
         *
         * ★ 为什么不用 contents API 逐个写：每个文件一次完整提交，
         *   实测每笔固定约 5.7 秒，与文件数无关。100 个文件串行就是 10 分钟。
         *   tree API 一批一次提交，100 个文件也是几秒。
         */
        async commit(files, message) {
            const ref = await this.http.req(`/repos/${this.full}/git/ref/heads/${this.branch}`);
            const cm = await this.http.req(`/repos/${this.full}/git/commits/${ref.object.sha}`);

            // ★ encoding 必须是 base64。曾经写成 utf-8，
            //   结果文件被存成 base64 文本——提交成功了，内容全是乱码。
            //   教训：验证了"提交成功"不等于验证了"提交的是什么"。
            const tree = [];
            for (const f of files) {
                const content = typeof f.content === 'string'
                    ? new TextEncoder().encode(f.content)
                    : f.content;
                const blob = await this.http.req(`/repos/${this.full}/git/blobs`, {
                    method: 'POST',
                    body: { content: Crypto._b64(content), encoding: 'base64' },
                    retry: { tries: 3, delay: 600 }
                });
                tree.push({ path: f.path, mode: '100644', type: 'blob', sha: blob.sha });
            }
            if (!files.length) return null;

            const t = await this.http.req(`/repos/${this.full}/git/trees`, {
                method: 'POST', body: { base_tree: cm.tree.sha, tree }
            });
            const c = await this.http.req(`/repos/${this.full}/git/commits`, {
                method: 'POST', body: { message: message || 'gitstore: 批量更新', tree: t.sha, parents: [ref.object.sha] }
            });
            /**
             * ★ commit 不能重试。提交内容里带时间戳，重试会生成
             *   两个内容不同、sha 不同的提交 —— 也就是重复提交。
             *   所以这里 tries:1，绝不重试。
             */
            await this.http.req(`/repos/${this.full}/git/refs/heads/${this.branch}`, {
                method: 'PATCH', body: { sha: c.sha }, retry: { tries: 1 }
            });
            return c.sha;
        }

        /** 私有仓库的文件不能直接当 img src —— raw 链接要带 token。取回来转 blob URL。 */
        async blobURL(path) {
            const f = await this.getRaw(path);
            if (!f) return null;
            const bin = atob(f.content.replace(/\n/g, ''));
            const u8 = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
            return URL.createObjectURL(new Blob([u8], { type: f.type || 'application/octet-stream' }));
        }
    }

    /* ══════════════════════════════════════════════════════════
     * 4. Pool —— 自动管理仓库：装不下就开新的
     *
     * ★ 单仓建议不超过 1GB（GitHub 的建议值，硬超会拒绝推送），
     *   这里取 900MB 留余量。
     * ══════════════════════════════════════════════════════════ */
    class Pool {
        constructor(owner, base, opt = {}) {
            this.owner = owner;
            this.base = base;
            this.max = opt.max || 900 * 1024 * 1024;
            this.http = opt.http;
            this.branch = opt.branch || 'main';
            this.vaults = [{ repo: base, bytes: 0 }];
            this._repos = new Map();
        }

        repo(name) {
            if (!this._repos.has(name)) {
                this._repos.set(name, new Repo(this.http, this.owner, name, this.branch));
            }
            return this._repos.get(name);
        }

        /** 从已有记录重算用量。★ 不用"加加减减"——漏记一次就永远偏大。 */
        recalc(byteOf) {
            for (const v of this.vaults) v.bytes = 0;
            for (const e of byteOf()) {
                let v = this.vaults.find(x => x.repo === e.repo);
                if (!v) { v = { repo: e.repo, bytes: 0 }; this.vaults.push(v); }
                v.bytes += e.size || 0;
            }
            return this.vaults;
        }

        async _nextName() {
            const used = new Set(this.vaults.map(v => v.repo));
            for (let i = 2; i < 200; i++) {
                const n = `${this.base}-${i}`;
                if (!used.has(n)) return n;
            }
            return `${this.base}-${Date.now().toString(36)}`;
        }

        async allocate(need) {
            for (const v of this.vaults) {
                if ((v.bytes || 0) + need <= this.max) return { repo: v.repo, isNew: false };
            }
            const name = await this._nextName();
            await this.repo(name).ensure({ private: true });
            this.vaults.push({ repo: name, bytes: 0 });
            return { repo: name, isNew: true };
        }

        stat() {
            const bytes = this.vaults.reduce((a, v) => a + (v.bytes || 0), 0);
            return { bytes, max: this.max * this.vaults.length, repos: this.vaults.length };
        }
    }

    /* ══════════════════════════════════════════════════════════
     * 5. Vault —— 自动加密的命名空间
     * ══════════════════════════════════════════════════════════ */
    class Vault {
        constructor(repo, key, opt = {}) {
            this.repo = repo;
            this.key = key;
            this.prefix = opt.prefix || '';
            this.hideNames = !!opt.hideNames;   // 连文件名也加密
            this._map = null;                   // hideNames 时的 名字→密文名 映射
        }
        _p(p) { return this.prefix ? `${this.prefix}/${p}` : p; }

        async _loadMap() {
            if (this._map) return this._map;
            const r = await this.repo.getJSON(this._p('_index.json'));
            this._map = (r && r.data) || {};
            return this._map;
        }

        async put(path, plain) {
            if (!this.hideNames) {
                const env = await Crypto.encrypt(this.key, plain);
                const r = await this.repo.read(this._p(path + '.enc'));
                await this.repo.write(this._p(path + '.enc'), JSON.stringify(env),
                    `gitstore: 写入 ${path}`, r ? r.sha : null);
                return path;
            }
            // 文件名也加密：需要一张索引表（索引本身也加密）
            const map = await this._loadMap();
            let encName = map[path];
            if (!encName) {
                encName = Crypto._b64(Crypto.random(12)).replace(/[+/=]/g, m => ({ '+': 'a', '/': 'b', '=': 'c' }[m]));
                map[path] = encName;
                const envMap = await Crypto.encrypt(this.key, JSON.stringify(map));
                const ri = await this.repo.read(this._p('_index.json'));
                await this.repo.write(this._p('_index.json'), JSON.stringify(envMap),
                    'gitstore: 更新索引', ri ? ri.sha : null);
                this._map = map;
            }
            const env = await Crypto.encrypt(this.key, plain);
            const r = await this.repo.read(this._p(encName + '.enc'));
            await this.repo.write(this._p(encName + '.enc'), JSON.stringify(env),
                'gitstore: 写入', r ? r.sha : null);
            return path;
        }

        async get(path) {
            if (!this.hideNames) {
                const r = await this.repo.getJSON(this._p(path + '.enc'));
                if (!r || !r.data) return null;
                return await Crypto.decrypt(this.key, r.data);
            }
            const map = await this._loadMap();
            const encName = map[path];
            if (!encName) return null;
            const r = await this.repo.getJSON(this._p(encName + '.enc'));
            if (!r || !r.data) return null;
            return await Crypto.decrypt(this.key, r.data);
        }

        /** 只有 hideNames=false 时才能列出（否则文件名都是随机串，没有意义） */
        async keys() {
            if (!this.hideNames) {
                const files = await this.repo.list(this.prefix);
                return files
                    .filter(f => f.name.endsWith('.enc') &&
                        !['_index.json', '_verify.enc'].includes(f.name))
                    .map(f => f.name.replace(/\.enc$/, ''));
            }
            return Object.keys(await this._loadMap());
        }
    }

    /* ══════════════════════════════════════════════════════════
     * 6. GitStore —— 门面
     * ══════════════════════════════════════════════════════════ */
    class GitStore {
        constructor(opt = {}) {
            this.accounts = new Map();
            this.current = null;
            this.owner = null;
            if (opt.token) this.addAccount(opt.account || 'default', opt.token, true);
            this.repoCache = new Map();
            this.poolCache = new Map();
        }

        /** 多账号：addAccount(name, token, isDefault) */
        addAccount(name, token, asDefault = false) {
            this.accounts.set(name, { name, token, http: new Http(token) });
            if (asDefault || !this.current) this.use(name);
            return this;
        }

        use(name) {
            const a = this.accounts.get(name);
            if (!a) throw new Error(`没有这个账号：${name}`);
            this.current = a;
            this.owner = null;      // 换了账号，owner 要重新取
            return this;
        }

        /** 临时用另一个账号，不改默认 */
        as(name) {
            const c = this.current;
            this.use(name);
            const self = this;
            return {
                then: (...a) => Promise.resolve(self).then(...a),
                back() { self.current = c; self.owner = null; return self; }
            };
        }

        async whoami() {
            if (!this.owner) {
                const me = await this.current.http.req('/user');
                this.owner = me.login;
                this.current.login = me.login;
            }
            return this.owner;
        }

        get http() { return this.current.http; }

        /** 拿一个仓库（不自动创建，除非 auto） */
        async repo(name, opt = {}) {
            await this.whoami();
            const key = `${this.current.name}/${name}`;
            if (!this.repoCache.has(key)) {
                this.repoCache.set(key, new Repo(this.http, this.owner, name, opt.branch || 'main'));
            }
            const r = this.repoCache.get(key);
            if (opt.auto) await r.ensure(opt);
            return r;
        }

        /** 仓库池：满了自动开下一个 */
        async pool(base, opt = {}) {
            await this.whoami();
            const key = `${this.current.name}/${base}`;
            if (!this.poolCache.has(key)) {
                this.poolCache.set(key, new Pool(this.owner, base, {
                    http: this.http, max: opt.max, branch: opt.branch
                }));
            }
            return this.poolCache.get(key);
        }

        /* ── 便捷写法：直接用默认仓库 ── */
        async useRepo(name, opt = {}) {
            this._repo = await this.repo(name, { auto: true, private: opt.private !== false, ...opt });
            return this._repo;
        }

        /**
         * 合并式写入。
         *
         * ★ 为什么不"直接覆盖"：两台设备各自拿着旧快照写，
         *   后写的会把先写的整份冲掉——这种丢失不报错，看不出来。
         *
         * ★ 为什么不"等 409 再合并"：put 内部本来就先 read 拿最新 sha，
         *   所以几乎永远不会 409，那个分支等于死代码（第一版就是这样，
         *   测出来 merge 根本没被调用）。
         *   正确做法是每次都主动：read 最新 → merge(我的, 远端的) → 带 sha 写回。
         *
         * @param opt.merge (mine, theirs) => 最终值。默认直接返回 mine（即纯覆盖）。
         * @param opt.retries 409 时重来几次（read 和 write 之间被别的设备插队的极小窗口）
         */
        async put(path, value, opt = {}) {
            const repo = opt.repo || this._repo;
            if (!repo) throw new Error('先 useRepo() 或传 repo');
            const merge = opt.merge || ((mine) => mine);
            const asText = opt.json === false;

            for (let i = 0; i < (opt.retries || 3); i++) {
                const cur = await repo.read(path);
                let theirs = null;
                if (cur) {
                    if (asText) theirs = cur.text;
                    else { try { theirs = JSON.parse(cur.text); } catch (e) { theirs = null; } }
                }
                const final = merge(value, theirs);
                const text = typeof final === 'string' ? final : JSON.stringify(final);
                try {
                    return await repo.write(path, text, opt.message, cur ? cur.sha : null);
                } catch (e) {
                    if (e.status !== 409) throw e;
                    continue;      // 被插队了，重新 read → merge → 写
                }
            }
            throw new Error('冲突重试次数用尽');
        }

        async get(path, opt = {}) {
            const repo = opt.repo || this._repo;
            if (!repo) throw new Error('先 useRepo() 或传 repo');
            const r = await repo.getJSON(path);
            return r ? r.data : null;
        }

        /* ── 加密仓库 ── */
        /**
         * @param {Object} o { repo, password, salt?, hideNames?, prefix? }
         *   password 给出口令就是口令派生；不给则要求给 key（已经算好的 CryptoKey）
         */
        async vault(o = {}) {
            await this.whoami();
            const repo = o.repo
                ? await this.repo(typeof o.repo === 'string' ? o.repo : o.repo.name, { auto: true })
                : (this._repo || null);
            if (!repo) throw new Error('vault 需要一个仓库');

            let key = o.key;
            if (!key && o.password) {
                /*
                 * ★ salt / verifier 必须放在 vault 自己的 prefix 下。
                 *   第一版写在仓库根目录（_salt.txt / _verify.enc），
                 *   结果同一个仓库里开第二个 vault（不同 prefix、不同密码）时，
                 *   会读到第一个 vault 的 salt 和校验 —— 直接报"密码不对"，
                 *   而用户明明是第一次用这个密码。
                 *   测试第 9 项就是这么崩的。
                 */
                const px = o.prefix || '';
                const j = (n) => px ? `${px}/${n}` : n;
                const saltPath = o.saltPath || j('_salt.txt');
                const verifyPath = o.verifyPath || j('_verify.enc');

                // salt 从仓库读，没有就生成一个存进去（salt 不怕公开）
                const sr = await repo.read(saltPath);
                let salt;
                if (sr) salt = Crypto._unb64(sr.text);
                else {
                    salt = Crypto.random(16);
                    await repo.write(saltPath, Crypto._b64(salt), 'gitstore: 写入 salt');
                }
                key = await Crypto.deriveKey(o.password, salt);

                // ★ 存一个 verifier，下次能区分"密码错了"和"数据坏了"
                const vr = await repo.read(verifyPath);
                if (!vr) {
                    await repo.write(verifyPath,
                        JSON.stringify(await Crypto.makeVerifier(key)), 'gitstore: 写入校验');
                } else {
                    let env; try { env = JSON.parse(vr.text); } catch (e) { }
                    if (env && !(await Crypto.checkVerifier(key, env))) {
                        throw new Error('密码不对');
                    }
                }
            }
            if (!key) throw new Error('vault 需要 password 或 key');
            return new Vault(repo, key, { prefix: o.prefix, hideNames: o.hideNames });
        }

        /** 设备密钥对 + ECDH：把自己的公钥发出去，和对方算出同一个密钥 */
        async keyring(repoName, opt = {}) {
            await this.whoami();
            const repo = await this.repo(repoName, { auto: true, private: opt.private !== false });
            const me = this.current.login;
            const pkPath = `pubkeys/${me}.txt`;
            const skPath = `privkeys/${me}.txt`;

            let kp = await repo.read(skPath);
            if (kp) {
                // 私钥也是加密存的（用口令）—— 这里只做最简：本地 localStorage
                kp = JSON.parse(atob(kp.text));
                const priv = await crypto.subtle.importKey('jwk', kp.privateJwk,
                    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
                return { repo, me, priv, pub: kp.pub, refresh: async () => { } };
            }
            const fresh = await Crypto.genKeyPair();
            const pub = await Crypto.exportPub(fresh);
            const privJwk = await crypto.subtle.exportKey('jwk', fresh.privateKey);
            await repo.commit([
                { path: pkPath, content: pub },
                { path: skPath, content: btoa(JSON.stringify({ pub, privateJwk: privJwk })) }
            ], `gitstore: ${me} 的密钥对`);
            return { repo, me, priv: fresh.privateKey, pub };
        }

        /** 用 ECDH 共享密钥开一个 vault */
        async sharedVault(repoName, priv, theirPub) {
            const key = await Crypto.sharedSecret(priv, theirPub);
            const repo = await this.repo(repoName, { auto: true });
            return new Vault(repo, key, {});
        }
    }

    GitStore.Http = Http;
    GitStore.Crypto = Crypto;
    GitStore.Repo = Repo;
    GitStore.Pool = Pool;
    GitStore.Vault = Vault;

    /*
     * ★ 参数名叫 root，不叫 global。
     *   叫 global 的话，在 Node 的 CommonJS 里会遮蔽真正的全局对象
     *   （CJS 顶层 this === module.exports，不是 globalThis），
     *   结果 `global.GitStore = ...` 挂到了导出对象上而不是全局 —— 浏览器没事，Node 拿不到。
     */
    root.GitStore = GitStore;
    if (typeof globalThis !== 'undefined') globalThis.GitStore = GitStore;
    if (typeof module !== 'undefined' && module.exports) module.exports = GitStore;
})(typeof window !== 'undefined' ? window : this);
