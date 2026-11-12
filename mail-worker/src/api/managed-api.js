import app from '../hono/hono';
import result from '../model/result';
import BizError from '../error/biz-error';
import cryptoUtils from '../utils/crypto-utils';
import roleService from '../service/role-service';
import KvConst from '../const/kv-const';

const enc = new TextEncoder();
const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
async function key(c) {
 if (!c.env.ACCOUNT_VAULT_KEY) throw new BizError('请先配置账户保险库密钥', 503);
 return crypto.subtle.importKey('raw', await crypto.subtle.digest('SHA-256', enc.encode(c.env.ACCOUNT_VAULT_KEY)), 'AES-GCM', false, ['encrypt','decrypt']);
}
async function seal(c, value, email) {
 const iv = crypto.getRandomValues(new Uint8Array(12));
 const data = await crypto.subtle.encrypt({name:'AES-GCM', iv, additionalData:enc.encode(email)}, await key(c), enc.encode(value));
 return b64(iv)+'.'+b64(data);
}
async function unseal(c, value, email) {
 const [iv,data] = value.split('.').map(x=>Uint8Array.from(atob(x), c=>c.charCodeAt(0)));
 return new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM',iv,additionalData:enc.encode(email)},await key(c),data));
}
app.use('/managed/*', async(c,next)=>{
 if(c.get('user')?.email !== c.env.admin) throw new BizError('仅管理员可管理账户',403);
 c.header('Cache-Control','no-store');
 await c.env.db.prepare(`CREATE TABLE IF NOT EXISTS managed_account (email TEXT PRIMARY KEY COLLATE NOCASE, secret TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', state TEXT NOT NULL DEFAULT 'temporary', created_at TEXT DEFAULT CURRENT_TIMESTAMP)`).run();
 await next();
});
// Dashboard text variables arrive as JSON strings; wrangler arrays arrive as arrays.
function domains(c) {
 let value=c.env.domain;
 try { if(typeof value==='string') value=JSON.parse(value); }
 catch { throw new BizError('邮箱域名配置必须是 JSON 数组'); }
 if(!Array.isArray(value)||!value.length||value.some(d=>typeof d!=='string'||!validDomain(d.trim().toLowerCase()))) throw new BizError('邮箱域名配置无效');
 return [...new Set(value.map(d=>d.trim().toLowerCase()))];
}
function validDomain(d) {
 return d.length<=253 && d.includes('.') && d.split('.').every(label=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
}
function selectedDomain(c, input) {
 const allowed=domains(c);
 const domain=input===undefined?allowed[0]:input;
 if(typeof domain!=='string'||!allowed.includes(domain)) throw new BizError('请选择完整且有效的邮箱域名');
 return domain;
}
const first=['lin','wei','ming','yan','chen','yu','hao','ning','jason','alex','emma','lucas','olivia','ethan','sophia','leo'];
const last=['chen','wang','li','zhang','liu','zhou','wu','xu','sun','lin','zhao','huang'];
const pick=a=>a[crypto.getRandomValues(new Uint32Array(1))[0]%a.length];
app.get('/managed/config',c=>c.json(result.ok({domains:domains(c)})));
app.get('/managed/list',async c=>c.json(result.ok((await c.env.db.prepare('SELECT email,note,state,created_at FROM managed_account ORDER BY created_at DESC,email').all()).results)));
app.post('/managed/create',async c=>{
 const body=await c.req.json();
 const domain=selectedDomain(c,body.domain);
 let prefix=(body.prefix||'').trim().toLowerCase();
 if(prefix && !/^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/.test(prefix)) throw new BizError('前缀请使用字母、数字及分隔符');
 if(prefix.length>40) throw new BizError('前缀最多40个字符');
 if(!prefix) {
  const base=pick(first)+'.'+pick(last);
  for(let i=0;i<30;i++) {
   prefix=base+(i?String(10+crypto.getRandomValues(new Uint32Array(1))[0]%990):'');
   if(!await c.env.db.prepare('SELECT 1 FROM account WHERE email = ? COLLATE NOCASE').bind(prefix+'@'+domain).first()) break;
  }
 }
 const email=prefix+'@'+domain;
 if(await c.env.db.prepare('SELECT 1 FROM account WHERE email=? COLLATE NOCASE').bind(email).first()) throw new BizError('邮箱已存在，请换一个前缀');
 const password='Aa9!'+b64(crypto.getRandomValues(new Uint8Array(18)));
 const secret=await seal(c,password,email);
 const {salt,hash}=await cryptoUtils.hashPassword(password);
 const role=await roleService.selectDefaultRole(c);
 if(!role) throw new BizError('请设置默认角色');
 await c.env.db.batch([
  c.env.db.prepare('INSERT INTO managed_account(email,secret) VALUES (?,?)').bind(email,secret),
  c.env.db.prepare('INSERT INTO user(email,password,salt,type) VALUES (?,?,?,?)').bind(email,hash,salt,role.roleId),
  c.env.db.prepare('INSERT INTO account(email,name,user_id) SELECT ?,?,user_id FROM user WHERE email=? COLLATE NOCASE').bind(email,prefix,email)
 ]);
 return c.json(result.ok({email}));
});
async function managed(c) {
 const email=c.req.query('email');
 const row=await c.env.db.prepare('SELECT * FROM managed_account WHERE email=?').bind(email||'').first();
 if(!row) throw new BizError('账户不存在',404);
 return row;
}
app.get('/managed/password',async c=>{
 const row=await managed(c);
 return c.json(result.ok({password:await unseal(c,row.secret,row.email)}));
});
app.put('/managed/state',async c=>{
 const row=await managed(c);
 const {state,note=''}=await c.req.json();
 if(!['temporary','saved','deleted'].includes(state)||typeof note!=='string'||note.length>500) throw new BizError('无效参数');
 const user=await c.env.db.prepare('SELECT user_id FROM user WHERE email=? COLLATE NOCASE').bind(row.email).first();
 if(!user) throw new BizError('邮箱账户已被移除');
 const deleted=state==='deleted'?1:0;
 await c.env.db.batch([
  c.env.db.prepare('UPDATE managed_account SET state=?,note=? WHERE email=?').bind(state,note,row.email),
  c.env.db.prepare('UPDATE user SET status=?,is_del=? WHERE user_id=?').bind(deleted,deleted,user.user_id),
  c.env.db.prepare('UPDATE account SET is_del=? WHERE user_id=?').bind(deleted,user.user_id)
 ]);
 await c.env.kv.delete(KvConst.AUTH_INFO+user.user_id);
 return c.json(result.ok());
});
app.get('/managed/messages',async c=>{
 const row=await managed(c);
 const before=Number(c.req.query('before'))||Number.MAX_SAFE_INTEGER;
 const rows=await c.env.db.prepare(`SELECT e.email_id,e.subject,e.send_email,e.name,e.create_time,e.unread,e.code FROM email e JOIN account a ON a.account_id=e.account_id WHERE a.email=? COLLATE NOCASE AND e.type=0 AND e.is_del=0 AND e.email_id<? ORDER BY e.email_id DESC LIMIT 50`).bind(row.email,before).all();
 return c.json(result.ok(rows.results));
});
app.get('/managed/message',async c=>{
 const row=await managed(c);
 const mail=await c.env.db.prepare(`SELECT e.email_id,e.subject,e.send_email,e.text,e.content,e.code,e.create_time FROM email e JOIN account a ON a.account_id=e.account_id WHERE a.email=? COLLATE NOCASE AND e.email_id=? AND e.type=0 AND e.is_del=0`).bind(row.email,Number(c.req.query('id'))).first();
 if(!mail) throw new BizError('邮件不存在',404);
 await c.env.db.prepare('UPDATE email SET unread=1 WHERE email_id=?').bind(mail.email_id).run();
 return c.json(result.ok(mail));
});

// Repair only malformed addresses from the previous domain parsing bug.
app.post('/managed/repair',async c=>{
 const row=await managed(c);
 const [prefix,oldDomain,...extra]=row.email.split('@');
 if(extra.length||!prefix||validDomain(oldDomain||'')) throw new BizError('该账户无需修复');
 const body=await c.req.json();
 const email=prefix+'@'+selectedDomain(c,body.domain);
 if(await c.env.db.prepare('SELECT 1 FROM account WHERE email=? COLLATE NOCASE').bind(email).first() || await c.env.db.prepare('SELECT 1 FROM user WHERE email=? COLLATE NOCASE').bind(email).first()) throw new BizError('正确地址已存在，请保留原账户并使用其他前缀');
 const user=await c.env.db.prepare('SELECT user_id FROM user WHERE email=? COLLATE NOCASE').bind(row.email).first();
 if(!user) throw new BizError('原账户不存在');
 const secret=await seal(c,await unseal(c,row.secret,row.email),email);
 await c.env.db.batch([
  c.env.db.prepare('UPDATE managed_account SET email=?,secret=? WHERE email=?').bind(email,secret,row.email),
  c.env.db.prepare('UPDATE user SET email=? WHERE user_id=?').bind(email,user.user_id),
  c.env.db.prepare('UPDATE account SET email=? WHERE email=? COLLATE NOCASE AND user_id=?').bind(email,row.email,user.user_id)
 ]);
 await c.env.kv.delete(KvConst.AUTH_INFO+user.user_id);
 return c.json(result.ok({email}));
});
