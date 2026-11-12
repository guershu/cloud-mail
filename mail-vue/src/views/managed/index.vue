<script setup>
import {ref,computed,onMounted,onUnmounted} from 'vue';
import {ElMessage,ElMessageBox} from 'element-plus';
import DOMPurify from 'dompurify';
import http from '@/axios';
const accounts=ref([]),selected=ref(null),messages=ref([]),mail=ref(null),query=ref(''),filter=ref('active'),busy=ref(false),loading=ref(false),error=ref(''),prefix=ref(''),domain=ref(''),domains=ref([]),note=ref(''),password=ref('');
let generation=0,timer,checking=false;
const filtered=computed(()=>accounts.value.filter(a=>(filter.value==='active'?a.state!=='deleted':a.state===filter.value)&&(a.email+' '+a.note).toLowerCase().includes(query.value.toLowerCase())));
const html=computed(()=>'<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; img-src data:; base-uri \'none\'; form-action \'none\'"><style>body{font:15px/1.7 sans-serif;overflow-wrap:anywhere;padding:16px}img{max-width:100%}</style>'+DOMPurify.sanitize(mail.value?.content||'',{FORBID_TAGS:['form','iframe','object','embed'],FORBID_ATTR:['srcset']}));
const params=()=>({email:selected.value.email});
async function refreshAccounts(){accounts.value=await http.get('/managed/list');}
async function choose(a){generation++; selected.value=a;note.value=a.note;password.value='';mail.value=null;messages.value=[];await refreshMail();}
async function refreshMail(){
 if(!selected.value)return;
 const g=generation;loading.value=true;error.value='';
 try{const data=await http.get('/managed/messages',{params:params()});if(g===generation)messages.value=data;}
 catch(e){if(g===generation)error.value='邮件加载失败，请重试';}
 finally{if(g===generation)loading.value=false;}
}
async function repair(){busy.value=true;try{const a=await http.post('/managed/repair',{domain:domain.value},{params:params()});await refreshAccounts();await choose(accounts.value.find(x=>x.email===a.email));ElMessage.success('邮箱地址已修复，原密码保留');}catch{}finally{busy.value=false;}}
async function create(){busy.value=true;try{const a=await http.post('/managed/create',{prefix:prefix.value,domain:domain.value});prefix.value='';filter.value='active';query.value='';await refreshAccounts();await choose(accounts.value.find(x=>x.email===a.email));ElMessage.success('账户已创建，可立即收信');}catch{}finally{busy.value=false;}}
async function update(state){if(!selected.value)return;const email=selected.value.email;try{if(state==='deleted')await ElMessageBox.confirm('移入回收站后，该账户将停止登录和收信，已有邮件保留。','删除账户',{type:'warning'});await http.put('/managed/state',{state,note:note.value},{params:{email}});await refreshAccounts();await choose(accounts.value.find(x=>x.email===email));ElMessage.success('已保存');}catch{}}
async function reveal(){const g=generation;try{const data=await http.get('/managed/password',{params:params()});if(g===generation)password.value=data.password;}catch{}}
async function copy(value){try{await navigator.clipboard.writeText(value);ElMessage.success('已复制');}catch{ElMessage.error('无法访问剪贴板，请手动复制');}}
async function open(m){const g=generation;try{const data=await http.get('/managed/message',{params:{...params(),id:m.email_id}});if(g===generation){mail.value=data;m.unread=1;}}catch{}}
async function older(){if(!messages.value.length)return;const g=generation;try{const data=await http.get('/managed/messages',{params:{...params(),before:messages.value.at(-1).email_id}});if(g===generation){messages.value.push(...data);if(!data.length)ElMessage.info('没有更早的邮件');}}catch{}}
onMounted(async()=>{try{const cfg=await http.get('/managed/config');domains.value=cfg.domains;domain.value=domains.value[0];await refreshAccounts();}catch{error.value='无法加载账户，请确认使用管理员登录';}timer=setInterval(async()=>{if(!selected.value||document.hidden||checking||loading.value)return;checking=true;try{await refreshMail();}finally{checking=false;}},10000);});
onUnmounted(()=>{clearInterval(timer);generation++;password.value='';});
</script>
<template>
<section class="workspace">
 <header><div><small>MAIL WORKSPACE</small><h1>账户管理</h1><p>创建一个邮箱，在这里等待它的下一封来信。</p></div><el-tag type="success">每 10 秒自动检查来信</el-tag></header>
 <div class="create"><el-input v-model="prefix" placeholder="留空生成姓名＋数字，例如 jasonwang27" aria-label="邮箱前缀"/><el-select v-model="domain" aria-label="邮箱域名"><el-option v-for="d in domains" :key="d" :value="d" :label="'@'+d"/></el-select><el-button type="primary" :loading="busy" :disabled="!domain" @click="create">＋ 快速创建</el-button></div>
 <p class="hint">默认使用常见英文名＋姓氏拼写＋简短数字，仅含英文字母和数字。密码自动生成并加密保存。</p>
 <el-alert v-if="error" :title="error" type="error" :closable="false"/>
 <div class="panels">
  <aside><div class="filters"><el-input v-model="query" placeholder="搜索邮箱或备注" clearable aria-label="搜索账户"/><el-select v-model="filter" aria-label="账户状态"><el-option label="全部使用中" value="active"/><el-option label="临时" value="temporary"/><el-option label="已保存" value="saved"/><el-option label="回收站" value="deleted"/></el-select></div>
   <p class="count">{{filtered.length}} 个账户</p>
   <button v-for="a in filtered" :key="a.email" class="account" :class="{chosen:selected?.email===a.email}" @click="choose(a)"><strong>{{a.email}}</strong><span>{{a.note||'暂无备注'}}</span><small>{{{temporary:'临时',saved:'已保存',deleted:'回收站'}[a.state]}} · {{a.created_at}}</small></button>
   <el-empty v-if="!filtered.length" description="没有符合条件的账户" :image-size="70"/>
  </aside>
  <main v-if="selected"><div class="identity"><el-alert v-if="selected.email.endsWith('@[') || !selected.email.split('@')[1]?.includes('.')" type="error" :closable="false"><template #title>此地址不完整，请先修复 <el-button :loading="busy" :disabled="!domain" @click="repair">修复为 @{{domain}}</el-button></template></el-alert><h2>{{selected.email}}</h2><div class="actions"><el-button @click="copy(selected.email)">复制邮箱</el-button><el-button @click="password?password='':reveal()">{{password?'隐藏密码':'查看密码'}}</el-button><el-button v-if="selected.state!=='deleted'" type="danger" plain @click="update('deleted')">删除</el-button><el-button v-else @click="update('temporary')">恢复账户</el-button></div><div v-if="password" class="password"><code>{{password}}</code><el-button text @click="copy(password)">复制密码</el-button></div><div class="notes"><el-input v-model="note" maxlength="500" placeholder="网站、用途或备注" aria-label="账户备注"/><el-button :disabled="selected.state==='deleted'" @click="update('saved')">保存账户</el-button></div></div>
   <div class="inbox-title"><h3>邮件预览</h3><el-button :loading="loading" @click="refreshMail">刷新</el-button></div>
   <div class="mail-grid"><div class="message-list"><button v-for="m in messages" :key="m.email_id" class="message" :class="{chosen:mail?.email_id===m.email_id}" @click="open(m)"><strong>{{m.unread===0?'● ':''}}{{m.subject||'（无主题）'}}</strong><span>{{m.name||m.send_email}}</span><small>{{m.create_time}}</small></button><el-empty v-if="!messages.length&&!loading" description="暂无邮件，发送一封测试邮件试试" :image-size="60"/><el-button v-if="messages.length>=50" text @click="older">加载更早邮件</el-button></div><article v-if="mail"><h3>{{mail.subject}}</h3><p>{{mail.send_email}} · {{mail.create_time}}</p><el-button v-if="mail.code" @click="copy(mail.code)">复制验证码 {{mail.code}}</el-button><iframe v-if="mail.content" title="邮件正文" sandbox="allow-popups allow-popups-to-escape-sandbox" referrerpolicy="no-referrer" :srcdoc="html"/><pre v-else>{{mail.text}}</pre></article><div v-else class="placeholder">选择一封邮件查看正文</div></div>
  </main><div v-else class="placeholder">创建或选择账户，即可查看对应邮件</div>
 </div>
</section>
</template>
<style scoped>
.workspace{padding:28px;background:#f6f7f9;color:#243047;min-height:100%;box-sizing:border-box}header{display:flex;justify-content:space-between;align-items:center}small{font-size:11px;color:#778296;letter-spacing:.04em}h1{font-size:27px;margin:6px 0}h2{font-size:18px;overflow-wrap:anywhere}h3{font-size:15px}p,.hint{font-size:13px;color:#758096}.create{display:flex;gap:10px;margin-top:24px;max-width:800px}.create .el-select{width:220px;flex-shrink:0}.hint{margin-bottom:24px}.panels{display:grid;grid-template-columns:300px minmax(0,1fr);background:white;border:1px solid #e4e8ee;min-height:580px}aside{border-right:1px solid #e4e8ee;max-height:800px;overflow:auto}.filters{padding:16px;display:grid;gap:10px}.count{padding:0 16px}.account,.message{font:inherit;background:none;border:0;border-bottom:1px solid #edf0f4;width:100%;text-align:left;padding:16px;cursor:pointer;display:grid;gap:8px;color:inherit;overflow-wrap:anywhere}.account strong,.message strong{font-size:13px}.account span,.message span{font-size:12px;color:#7a8393}.account:hover,.message:hover{background:#f8fafc}.chosen{background:#edf4ff!important;box-shadow:inset 3px 0 #4876d0}.identity{padding:20px;border-bottom:1px solid #e4e8ee}.actions{display:flex;flex-wrap:wrap;gap:8px}.actions .el-button{margin:0}.notes{display:flex;gap:8px;margin-top:16px}.password{padding:12px;background:#f5f7fa;margin-top:12px;overflow-wrap:anywhere}code,small{font-variant-numeric:tabular-nums}.inbox-title{padding:0 20px;display:flex;align-items:center;justify-content:space-between}.mail-grid{display:grid;grid-template-columns:240px minmax(0,1fr);border-top:1px solid #edf0f4;min-height:390px}.message-list{max-height:650px;overflow:auto;border-right:1px solid #edf0f4}article{padding:18px;min-width:0}article p{overflow-wrap:anywhere}iframe{width:100%;height:420px;border:0;margin-top:12px}pre{white-space:pre-wrap;overflow-wrap:anywhere}.placeholder{display:grid;place-content:center;padding:30px;color:#8b94a3;font-size:14px}@media(max-width:1100px){.panels{grid-template-columns:240px minmax(0,1fr)}.mail-grid{grid-template-columns:1fr}.message-list{max-height:260px}}@media(max-width:700px){.workspace{padding:14px}header{display:block}.panels{grid-template-columns:1fr}aside{max-height:300px}.create{flex-wrap:wrap}.create .el-select{width:100%}.identity{padding:14px}}
</style>
