// Pure parser of synthetic envelopes shaped like official Telegram Business Bot API updates.
// No network/token/session support. The synthetic marker is a convention, not provenance proof.
export function parseSyntheticBusinessUpdate(envelope, { connectionId, ownerUserId, chats, now }) {
  if (envelope?.synthetic !== true || !/^synthetic-[a-z0-9-]+$/.test(connectionId ?? '') || !Number.isSafeInteger(ownerUserId) || !Number.isFinite(now) || !Array.isArray(chats)) throw new Error('Synthetic configuration required');
  const update=envelope.update;
  if (!update || !Number.isSafeInteger(update.update_id) || update.update_id<0) return [];
  const kinds=['business_connection','business_message','edited_business_message','deleted_business_messages'].filter(k=>Object.hasOwn(update,k));
  if(kinds.length!==1) return [];
  const kind=kinds[0], value=update[kind];
  if(!value || typeof value!=='object') return [];
  if(kind==='business_connection') return value.id===connectionId && value.user?.id===ownerUserId && value.is_enabled===false ? chats.map(c=>({type:'revoke',chatId:c.id})) : [];
  if(value.business_connection_id!==connectionId || value.chat?.type!=='private') return [];
  const chat=chats.find(c=>Number.isSafeInteger(c.telegramChatId) && c.telegramChatId===value.chat.id && /^synthetic-[a-z0-9-]+$/.test(c.id) && c.participantsConsented===true && c.consentUntil>now);
  if(!chat) return [];
  const base={source:'synthetic',chatId:chat.id};
  if(kind==='deleted_business_messages') return Array.isArray(value.message_ids) && value.message_ids.length<=100 ? value.message_ids.filter(id=>Number.isSafeInteger(id)&&id>0).map(id=>({...base,type:'delete',id:'msg-'+id})) : [];
  if(!Number.isSafeInteger(value.message_id)||value.message_id<=0 || !Number.isSafeInteger(value.date) || value.date*1000<=chat.activatedAt || value.date*1000>now || now-value.date*1000>=3600000 || value.from?.id!==value.chat.id || value.from.id===ownerUserId || value.from.is_bot!==false || typeof value.text!=='string' || !value.text.length || value.text.length>2000 || ['photo','document','video','voice','audio','caption','forward_origin','sender_business_bot','media_group_id','reply_to_message','external_reply','quote'].some(k=>Object.hasOwn(value,k))) return [];
  return [{...base,type:kind==='business_message'?'new':'edit',id:'msg-'+value.message_id,direction:'incoming',receivedAt:value.date*1000,text:value.text}];
}
