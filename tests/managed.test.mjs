import {test} from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
function setup(){
 const db=new DatabaseSync(':memory:');
 db.exec(`CREATE TABLE user(user_id INTEGER PRIMARY KEY,email TEXT UNIQUE,password TEXT,salt TEXT,type INTEGER,status INTEGER DEFAULT 0,is_del INTEGER DEFAULT 0); CREATE TABLE account(account_id INTEGER PRIMARY KEY,email TEXT UNIQUE,name TEXT,user_id INTEGER,is_del INTEGER DEFAULT 0); CREATE TABLE email(email_id INTEGER PRIMARY KEY,account_id INTEGER,subject TEXT,send_email TEXT,name TEXT,create_time TEXT,unread INTEGER,code TEXT,type INTEGER,is_del INTEGER,text TEXT,content TEXT);`);
 const prepare=sql=>{let args=[];return {bind(...a){args=a;return this},async run(){return db.prepare(sql).run(...args)},async first(){return db.prepare(sql).get(...args)},async all(){return {results:db.prepare(sql).all(...args)}}}};
 const routes={},app={use(p,f){routes.middleware=f}};
 for(const method of ['get','post','put'])app[method]=(p,f)=>routes[method+p]=f;
 let source=readFileSync(new URL('../mail-worker/src/api/managed-api.js',import.meta.url),'utf8').replace(/^import .*;\n/gm,'');
 vm.runInNewContext(source,{app,result:{ok:data=>({data})},BizError:Error,cryptoUtils:{hashPassword:async password=>({salt:'salt',hash:'hash:'+password})},roleService:{selectDefaultRole:async()=>({roleId:1})},KvConst:{AUTH_INFO:'auth:'},crypto,TextEncoder,TextDecoder,Uint8Array,Uint32Array,btoa,atob});
 const c={env:{admin:'admin@example.com',domain:['example.com'],ACCOUNT_VAULT_KEY:'test-fixture-key-not-for-production',db:{prepare,async batch(items){db.exec('BEGIN');try{for(const item of items)await item.run();db.exec('COMMIT')}catch(e){db.exec('ROLLBACK');throw e}}},kv:{delete:async()=>{}}},get:()=>({email:'admin@example.com'}),header(){},json:x=>x,req:{query:()=>undefined,json:async()=>({})}};
 return {db,routes,c};
}
test('create, encrypted password, account isolation, recycle and restore',async()=>{
 const {db,routes,c}=setup();await routes.middleware(c,async()=>{});
 c.req.json=async()=>({prefix:'lin.chen'});await routes['post/managed/create'](c);
 const stored=db.prepare('SELECT * FROM managed_account').get();assert.equal(stored.email,'lin.chen@example.com');assert.ok(!stored.secret.includes('Aa9!'));
 c.req.query=k=>({email:stored.email,id:'2'}[k]);const password=(await routes['get/managed/password'](c)).data.password;assert.ok(password.length>=24);
 assert.equal(db.prepare('SELECT password FROM user').get().password,'hash:'+password);
 db.exec(`INSERT INTO account VALUES(2,'other@example.com','other',2,0); INSERT INTO email VALUES(1,1,'mine','from','n','today',0,'',0,0,'body',''); INSERT INTO email VALUES(2,2,'private','from','n','today',0,'',0,0,'secret','')`);
 assert.equal((await routes['get/managed/messages'](c)).data.length,1);await assert.rejects(()=>routes['get/managed/message'](c));
 c.req.json=async()=>({state:'deleted'});await routes['put/managed/state'](c);assert.equal(db.prepare('SELECT is_del FROM user').get().is_del,1);
 c.req.json=async()=>({state:'saved',note:'test'});await routes['put/managed/state'](c);assert.equal(db.prepare('SELECT is_del FROM user').get().is_del,0);
 c.req.json=async()=>({prefix:'lin.chen'});await assert.rejects(()=>routes['post/managed/create'](c));assert.equal(db.prepare('SELECT count(*) AS n FROM user').get().n,1);
 c.get=()=>({email:'other@example.com'});await assert.rejects(()=>routes.middleware(c,async()=>{}));
});
test('JSON-string domain config yields complete addresses and rejects characters/substrings',async()=>{
 const {db,routes,c}=setup();c.env.domain='["canglin.asia"]';await routes.middleware(c,async()=>{});
 assert.equal(JSON.stringify((await routes['get/managed/config'](c)).data.domains),'["canglin.asia"]');
 for(const domain of ['[','canglin','asia','other.asia','',null]){c.req.json=async()=>({prefix:'yu.li',domain});await assert.rejects(()=>routes['post/managed/create'](c));}
 c.req.json=async()=>({prefix:'yu.li'});await routes['post/managed/create'](c);assert.equal(db.prepare('SELECT email FROM user').get().email,'yu.li@canglin.asia');
 for(const config of ['[', '"canglin.asia"', '[]','["["]']){c.env.domain=config;assert.throws(()=>routes['get/managed/config'](c));}
});
test('repair preserves password, identity, notes and messages',async()=>{
 const {db,routes,c}=setup();await routes.middleware(c,async()=>{});
 c.req.json=async()=>({prefix:'yu.li'});await routes['post/managed/create'](c);
 c.req.query=()=> 'yu.li@example.com';const password=(await routes['get/managed/password'](c)).data.password;
 const bytes=new TextEncoder(),iv=crypto.getRandomValues(new Uint8Array(12));
 const key=await crypto.subtle.importKey('raw',await crypto.subtle.digest('SHA-256',bytes.encode(c.env.ACCOUNT_VAULT_KEY)),'AES-GCM',false,['encrypt']);
 const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:bytes.encode('yu.li@[')},key,bytes.encode(password));
 const b64=x=>Buffer.from(x).toString('base64');
 db.prepare("UPDATE managed_account SET email='yu.li@[',secret=?,note='keep'").run(b64(iv)+'.'+b64(ciphertext));
 db.exec("UPDATE user SET email='yu.li@['; UPDATE account SET email='yu.li@['; INSERT INTO email VALUES(1,1,'mine','from','n','today',0,'',0,0,'body','')");
 c.env.domain='["canglin.asia"]';c.req.query=()=> 'yu.li@[';c.req.json=async()=>({domain:'canglin.asia'});
 await routes['post/managed/repair'](c);
 c.req.query=()=> 'yu.li@canglin.asia';assert.equal((await routes['get/managed/password'](c)).data.password,password);
 assert.equal(db.prepare('SELECT note FROM managed_account').get().note,'keep');assert.equal(db.prepare('SELECT user_id FROM user').get().user_id,1);
 assert.equal((await routes['get/managed/messages'](c)).data.length,1);
 await assert.rejects(()=>routes['post/managed/repair'](c));
});
