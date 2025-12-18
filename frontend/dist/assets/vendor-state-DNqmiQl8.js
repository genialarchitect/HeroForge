import{a as O,g as L,R as $}from"./vendor-react-CGkJ0Xct.js";var R={exports:{}},E={};/**
 * @license React
 * react-jsx-runtime.production.min.js
 *
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */var P;function M(){if(P)return E;P=1;var e=O(),o=Symbol.for("react.element"),s=Symbol.for("react.fragment"),f=Object.prototype.hasOwnProperty,d=e.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED.ReactCurrentOwner,_={key:!0,ref:!0,__self:!0,__source:!0};function S(v,u,a){var n,t={},r=null,i=null;a!==void 0&&(r=""+a),u.key!==void 0&&(r=""+u.key),u.ref!==void 0&&(i=u.ref);for(n in u)f.call(u,n)&&!_.hasOwnProperty(n)&&(t[n]=u[n]);if(v&&v.defaultProps)for(n in u=v.defaultProps,u)t[n]===void 0&&(t[n]=u[n]);return{$$typeof:o,type:v,key:r,ref:i,props:t,_owner:d.current}}return E.Fragment=s,E.jsx=S,E.jsxs=S,E}var T;function N(){return T||(T=1,R.exports=M()),R.exports}var ue=N();const B={},V=e=>{let o;const s=new Set,f=(n,t)=>{const r=typeof n=="function"?n(o):n;if(!Object.is(r,o)){const i=o;o=t??(typeof r!="object"||r===null)?r:Object.assign({},o,r),s.forEach(l=>l(o,i))}},d=()=>o,u={setState:f,getState:d,getInitialState:()=>a,subscribe:n=>(s.add(n),()=>s.delete(n)),destroy:()=>{(B?"production":void 0)!=="production"&&console.warn("[DEPRECATED] The `destroy` method will be unsupported in a future version. Instead use unsubscribe function returned by subscribe. Everything will be garbage-collected if store is garbage-collected."),s.clear()}},a=o=e(f,d,u);return u},G=e=>e?V(e):V;var x={exports:{}},g={},w={exports:{}},j={};/**
 * @license React
 * use-sync-external-store-shim.production.js
 *
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */var C;function Y(){if(C)return j;C=1;var e=O();function o(t,r){return t===r&&(t!==0||1/t===1/r)||t!==t&&r!==r}var s=typeof Object.is=="function"?Object.is:o,f=e.useState,d=e.useEffect,_=e.useLayoutEffect,S=e.useDebugValue;function v(t,r){var i=r(),l=f({inst:{value:i,getSnapshot:r}}),c=l[0].inst,m=l[1];return _(function(){c.value=i,c.getSnapshot=r,u(c)&&m({inst:c})},[t,i,r]),d(function(){return u(c)&&m({inst:c}),t(function(){u(c)&&m({inst:c})})},[t]),S(i),i}function u(t){var r=t.getSnapshot;t=t.value;try{var i=r();return!s(t,i)}catch{return!0}}function a(t,r){return r()}var n=typeof window>"u"||typeof window.document>"u"||typeof window.document.createElement>"u"?a:v;return j.useSyncExternalStore=e.useSyncExternalStore!==void 0?e.useSyncExternalStore:n,j}var k;function H(){return k||(k=1,w.exports=Y()),w.exports}/**
 * @license React
 * use-sync-external-store-shim/with-selector.production.js
 *
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */var z;function K(){if(z)return g;z=1;var e=O(),o=H();function s(a,n){return a===n&&(a!==0||1/a===1/n)||a!==a&&n!==n}var f=typeof Object.is=="function"?Object.is:s,d=o.useSyncExternalStore,_=e.useRef,S=e.useEffect,v=e.useMemo,u=e.useDebugValue;return g.useSyncExternalStoreWithSelector=function(a,n,t,r,i){var l=_(null);if(l.current===null){var c={hasValue:!1,value:null};l.current=c}else c=l.current;l=v(function(){function D(p){if(!I){if(I=!0,b=p,p=r(p),i!==void 0&&c.hasValue){var y=c.value;if(i(y,p))return h=y}return h=p}if(y=h,f(b,p))return y;var W=r(p);return i!==void 0&&i(y,W)?(b=p,y):(b=p,h=W)}var I=!1,b,h,q=t===void 0?null:t;return[function(){return D(n())},q===null?void 0:function(){return D(q())}]},[n,t,r,i]);var m=d(a,l[0],l[1]);return S(function(){c.hasValue=!0,c.value=m},[m]),u(m),m},g}var U;function Q(){return U||(U=1,x.exports=K()),x.exports}var X=Q();const Z=L(X),J={},{useDebugValue:ee}=$,{useSyncExternalStoreWithSelector:te}=Z;let A=!1;const re=e=>e;function ne(e,o=re,s){(J?"production":void 0)!=="production"&&s&&!A&&(console.warn("[DEPRECATED] Use `createWithEqualityFn` instead of `create` or use `useStoreWithEqualityFn` instead of `useStore`. They can be imported from 'zustand/traditional'. https://github.com/pmndrs/zustand/discussions/1937"),A=!0);const f=te(e.subscribe,e.getState,e.getServerState||e.getInitialState,o,s);return ee(f),f}const F=e=>{(J?"production":void 0)!=="production"&&typeof e!="function"&&console.warn("[DEPRECATED] Passing a vanilla store will be unsupported in a future version. Instead use `import { useStore } from 'zustand'`.");const o=typeof e=="function"?G(e):e,s=(f,d)=>ne(o,f,d);return Object.assign(s,o),s},ie=e=>e?F(e):F;export{ie as c,ue as j};
