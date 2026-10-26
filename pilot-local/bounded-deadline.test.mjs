import test from 'node:test';import assert from 'node:assert/strict';import {armDeadline} from './bounded-deadline.mjs';
test('fixed fifteen minute runtime deadline fires once and cancellation prevents late stop',()=>{
 let callback,delay,stops=0,cancels=0;const schedule=(fn,ms)=>{callback=fn;delay=ms;return {unref(){}};};
 const cancel=armDeadline(()=>{stops++;},{schedule,cancel:()=>cancels++});assert.equal(delay,900000);callback();callback();cancel();assert.equal(stops,1);
 const cancel2=armDeadline(()=>{stops++;},{schedule,cancel:()=>cancels++});cancel2();callback();assert.equal(stops,1);assert.equal(cancels,1);
 assert.throws(()=>armDeadline(()=>{}, {milliseconds:900001}));
});