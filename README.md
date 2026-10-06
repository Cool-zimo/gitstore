# gitstore.js

把 GitHub 当后端的轮子。

从 **AnyLearn / GitHub Drive / FaceHub / 粥粥记录 / 仓鼠** 里抽出来的共性能力。
那些坑每一个都是真踩过的，代码里写了为什么。

```html
<script src="https://cdn.jsdelivr.net/gh/Cool-zimo/gitstore@main/gitstore.js"></script>
```

国内访问不了 jsdelivr 就把 `gitstore.js` 拷到自己仓库里，一样用。

## 三行起步

```js
const store = new GitStore({ token });
await store.useRepo('my-data');            // 没有就自动建（默认私有）
await store.put('notes/a.json', { t: 'x' });
const a = await store.get('notes/a.json');
```

## 自动加密

```js
const v = await store.vault({ repo: 'my-data', password: 'xxx' });
await v.put('diary.txt', 'GitHub 上只看得到密文');
await v.get('diary.txt');                  // 自动解密
```

仓库里存的是 `{alg:'AES-GCM-256', iv, data}`，**明文不出现在任何地方**。

- 口令 → PBKDF2(250k, SHA-256) → AES-GCM-256
- salt 存仓库里没关系，salt 不怕公开
- 存了 verifier，所以能区分「密码错了」和「数据坏了」
- `hideNames: true` 连文件名也加密（代价：靠一张索引表，目录不可直接列）

## 两台设备不打架

```js
await store.put('data.json', mine, {
  merge: (mine, theirs) => ({ ...theirs, ...mine })
});
```

## 仓库满了自动开新的

```js
const pool = await store.pool('my-data', { max: 900*1024*1024 });
const { repo } = await pool.allocate(bytes);
pool.recalc(() => allFiles.map(f => ({repo: f.repo, size: f.size})));
```

## 多账号

```js
store.addAccount('main', tokenA, true);
store.addAccount('backup', tokenB);
store.use('backup');
```

## 一次提交写多个文件

```js
await repo.commit([{path:'a.txt', content:'…'}, …], 'message');
```

## API

| | |
|---|---|
| `new GitStore({token, account})` | |
| `addAccount(name, token, isDefault)` / `use(name)` / `as(name)` | 多账号 |
| `whoami()` | |
| `repo(name, {auto, private, branch})` | `auto:true` 自动建 |
| `useRepo(name)` | 设为默认仓库 |
| `put(path, value, {merge})` / `get(path)` | 合并式写入 |
| `vault({repo, password, hideNames, prefix})` | 自动加解密 |
| `pool(base, {max})` | 容量池 |
| `keyring(repo)` / `sharedVault(...)` | ECDH P-256 |
| `repo.commit(files, msg)` | 批量提交 |
| `repo.blobURL(path)` | 私有仓库文件转 blob URL |
| `GitStore.Crypto` | 加解密原语，可单独用 |

## 里面固化了哪些坑

| 坑 | 后果 |
|---|---|
| contents API 有 `max-age=60` 缓存 | 设备 A 写完 B 读不到，刷新也没用 → 全部 `no-store` |
| 写文件不带 sha | 强制覆盖，把别处刚写的整份抹掉，不报错 |
| blob API 的 `encoding` 写成 `utf-8` | 存成 base64 文本，提交"成功"但内容全乱 |
| 每文件一次提交 | 实测每笔固定 5.7 秒，100 个文件要 10 分钟 → tree API |
| commit 重试 | 提交带时间戳，重试 = 重复提交 → 永不重试 |
| 只认 429/502/503 | 一次 256MB 上传报 500 整批失败 → 加上 500 |
| 私有仓库用 raw 链接当 `img src` | 打不开，要取回转 blob URL |
| 并发 16 | GitHub 直接拒，实测 6 以内安全 |
| ECDH 用 X25519 | 和 P-256 混用永远协商不出相同密钥，**而且不报错** |

## 文档

https://cool-zimo.github.io/gitstore/
