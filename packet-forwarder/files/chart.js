/*! https://github.com/leeoniya/uPlot (v1.6.8) */
var uPlot=function(){"use strict";function n(n,e,r,t){var l;r=r||0;for(var i=2147483647>=(t=t||e.length-1);t-r>1;)n>e[l=i?r+t>>1:m((r+t)/2)]?r=l:t=l;return n-e[r]>e[t]-n?t:r}function e(n,e,r,t){for(var l=1==t?e:r;l>=e&&r>=l;l+=t)if(null!=n[l])return l;return-1}var r=[0,0];function t(n,e,t,l){return r[0]=0>t?H(n,-t):n,r[1]=0>l?H(e,-l):e,r}function l(n,e,r,l){var i,a,o,s=10==r?k:y;return n==e&&(n/=r,e*=r),l?(i=m(s(n)),a=g(s(e)),n=(o=t(b(r,i),b(r,a),i,a))[0],e=o[1]):(i=m(s(d(n))),a=m(s(d(e))),n=C(n,(o=t(b(r,i),b(r,a),i,a))[0]),e=Y(e,o[1])),[n,e]}function i(n,e,r,t){var i=l(n,e,r,t);return 0==n&&(i[0]=0),0==e&&(i[1]=0),i}var a={pad:0,soft:null,mode:0},o={min:a,max:a};function s(n,e,r,t){return j(r)?f(n,e,r):(a.pad=r,a.soft=t?0:null,a.mode=t?3:0,f(n,e,o))}function u(n,e){return null==n?e:n}function f(n,e,r){var t=r.min,l=r.max,i=u(t.pad,0),a=u(l.pad,0),o=u(t.hard,-S),s=u(l.hard,S),f=u(t.soft,S),c=u(l.soft,-S),v=u(t.mode,0),h=u(l.mode,0),p=e-n,g=p||d(e)||1e3,_=k(g),y=b(10,m(_)),M=H(C(n-g*(0==p?0==n?.1:1:i),y/10),6),z=f>n||1!=v&&(3!=v||M>f)&&(2!=v||f>M)?S:f,D=w(o,z>M&&n>=z?z:x(z,M)),T=H(Y(e+g*(0==p?0==e?.1:1:a),y/10),6),E=e>c||1!=h&&(3!=h||c>T)&&(2!=h||T>c)?-S:c,P=x(s,T>E&&E>=e?E:w(E,T));return D==P&&0==D&&(P=100),[D,P]}var c=new Intl.NumberFormat(navigator.language).format,v=Math,h=v.PI,d=v.abs,m=v.floor,p=v.round,g=v.ceil,x=v.min,w=v.max,b=v.pow,_=v.sqrt,k=v.log10,y=v.log2,M=(n,e)=>(void 0===e&&(e=1),v.asinh(n/e)),S=1/0;function z(n,e){return p(n/e)*e}function D(n,e,r){return x(w(n,e),r)}function T(n){return"function"==typeof n?n:()=>n}var E=n=>n,P=(n,e)=>e,A=()=>null,W=()=>!0;function Y(n,e){return g(n/e)*e}function C(n,e){return m(n/e)*e}function H(n,e){return p(n*(e=Math.pow(10,e)))/e}var F=new Map;function R(n){return((""+n).split(".")[1]||"").length}function L(n,e,r,t){for(var l=[],i=t.map(R),a=e;r>a;a++)for(var o=d(a),s=H(b(n,a),o),u=0;t.length>u;u++){var f=t[u]*s,c=(0>f||0>a?o:0)+(i[u]>a?i[u]:0),v=H(f,c);l.push(v),F.set(v,c)}return l}var I={},N=[null,null],O=Array.isArray;function V(n){return"string"==typeof n}function j(n){var e=!1;if(null!=n){var r=n.constructor;e=null==r||r==Object}return e}function G(n){return null!=n&&"object"==typeof n}function U(n,e){var r;if(e=e||j,O(n))r=n.map((n=>U(n,e)));else if(e(n))for(var t in r={},n)r[t]=U(n[t],e);else r=n;return r}function B(n){for(var e=arguments,r=1;e.length>r;r++){var t=e[r];for(var l in t)j(n[l])?B(n[l],U(t[l])):n[l]=U(t[l])}return n}function J(n,e,r){for(var t=0,l=void 0,i=-1;e.length>t;t++){var a=e[t];if(a>i){for(l=a-1;l>=0&&null==n[l];)n[l--]=null;for(l=a+1;r>l&&null==n[l];)n[i=l++]=null}}}var q="undefined"==typeof queueMicrotask?n=>Promise.resolve().then(n):queueMicrotask,Z="width",K="height",X="top",Q="bottom",$="left",nn="right",en="#000",rn="#0000",tn="mousemove",ln="mousedown",an="mouseup",on="mouseenter",sn="mouseleave",un="dblclick",fn="u-off",cn="u-label",vn=document,hn=window,dn=devicePixelRatio;function mn(n,e){if(null!=e){var r=n.classList;!r.contains(e)&&r.add(e)}}function pn(n,e){var r=n.classList;r.contains(e)&&r.remove(e)}function gn(n,e,r){n.style[e]=r+"px"}function xn(n,e,r,t){var l=vn.createElement(n);return null!=e&&mn(l,e),null!=r&&r.insertBefore(l,t),l}function wn(n,e){return xn("div",n,e)}function bn(n,e,r,t,l){n.style.transform="translate("+e+"px,"+r+"px)",0>e||0>r||e>t||r>l?mn(n,fn):pn(n,fn)}var _n={passive:!0},kn=B({capture:!0},_n);function yn(n,e,r,t){e.addEventListener(n,r,t?kn:_n)}function Mn(n,e,r,t){e.removeEventListener(n,r,t?kn:_n)}var Sn=["January","February","March","April","May","June","July","August","September","October","November","December"],zn=["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"];function Dn(n){return n.slice(0,3)}var Tn=zn.map(Dn),En=Sn.map(Dn),Pn={MMMM:Sn,MMM:En,WWWW:zn,WWW:Tn};function An(n){return(10>n?"0":"")+n}var Wn={YYYY:n=>n.getFullYear(),YY:n=>(n.getFullYear()+"").slice(2),MMMM:(n,e)=>e.MMMM[n.getMonth()],MMM:(n,e)=>e.MMM[n.getMonth()],MM:n=>An(n.getMonth()+1),M:n=>n.getMonth()+1,DD:n=>An(n.getDate()),D:n=>n.getDate(),WWWW:(n,e)=>e.WWWW[n.getDay()],WWW:(n,e)=>e.WWW[n.getDay()],HH:n=>An(n.getHours()),H:n=>n.getHours(),h:n=>{var e=n.getHours();return 0==e?12:e>12?e-12:e},AA:n=>12>n.getHours()?"AM":"PM",aa:n=>12>n.getHours()?"am":"pm",a:n=>12>n.getHours()?"a":"p",mm:n=>An(n.getMinutes()),m:n=>n.getMinutes(),ss:n=>An(n.getSeconds()),s:n=>n.getSeconds(),fff:n=>function(n){return(10>n?"00":100>n?"0":"")+n}(n.getMilliseconds())};function Yn(n,e){e=e||Pn;for(var r,t=[],l=/\{([a-z]+)\}|[^{]+/gi;r=l.exec(n);)t.push("{"==r[0][0]?Wn[r[1]]:r[0]);return n=>{for(var r="",l=0;t.length>l;l++)r+="string"==typeof t[l]?t[l]:t[l](n,e);return r}}var Cn=(new Intl.DateTimeFormat).resolvedOptions().timeZone,Hn=n=>n%1==0,Fn=[1,2,2.5,5],Rn=L(10,-16,0,Fn),Ln=L(10,0,16,Fn),In=Ln.filter(Hn),Nn=Rn.concat(Ln),On="{YYYY}",Vn="\n"+On,jn="{M}/{D}",Gn="\n"+jn,Un=Gn+"/{YY}",Bn="{aa}",Jn="{h}:{mm}"+Bn,qn="\n"+Jn,Zn=":{ss}",Kn=null;function Xn(n){var e=1e3*n,r=60*e,t=60*r,l=24*t,i=30*l,a=365*l;return[(1==n?L(10,0,3,Fn).filter(Hn):L(10,-3,0,Fn)).concat([e,5*e,10*e,15*e,30*e,r,5*r,10*r,15*r,30*r,t,2*t,3*t,4*t,6*t,8*t,12*t,l,2*l,3*l,4*l,5*l,6*l,7*l,8*l,9*l,10*l,15*l,i,2*i,3*i,4*i,6*i,a,2*a,5*a,10*a,25*a,50*a,100*a]),[[a,On,Kn,Kn,Kn,Kn,Kn,Kn,1],[28*l,"{MMM}",Vn,Kn,Kn,Kn,Kn,Kn,1],[l,jn,Vn,Kn,Kn,Kn,Kn,Kn,1],[t,"{h}"+Bn,Un,Kn,Gn,Kn,Kn,Kn,1],[r,Jn,Un,Kn,Gn,Kn,Kn,Kn,1],[e,Zn,Un+" "+Jn,Kn,Gn+" "+Jn,Kn,qn,Kn,1],[n,Zn+".{fff}",Un+" "+Jn,Kn,Gn+" "+Jn,Kn,qn,Kn,1]],function(e){return(o,s,u,f,c,v)=>{var h=[],d=c>=a,g=c>=i&&a>c,x=e(u),w=H(x*n,3),b=se(x.getFullYear(),d?0:x.getMonth(),g||d?1:x.getDate()),_=H(b*n,3);if(g||d)for(var k=g?c/i:0,y=d?c/a:0,M=w==_?w:H(se(b.getFullYear()+y,b.getMonth()+k,1)*n,3),S=new Date(p(M/n)),z=S.getFullYear(),D=S.getMonth(),T=0;f>=M;T++){var E=se(z+y*T,D+k*T,1),P=E-e(H(E*n,3));(M=H((+E+P)*n,3))>f||h.push(M)}else{var A=l>c?c:l,W=_+(m(u)-m(w))+Y(w-_,A);h.push(W);for(var C=e(W),F=C.getHours()+C.getMinutes()/r+C.getSeconds()/t,R=c/t,L=v/o.axes[s]._space;(W=H(W+c,1==n?0:3))<=f;)if(R>1){var I=m(H(F+R,6))%24,N=e(W).getHours()-I;N>1&&(N=-1),F=(F+R)%24,.7>H(((W-=N*t)-h[h.length-1])/c,3)*L||h.push(W)}else h.push(W)}return h}}]}var Qn=Xn(1),$n=Qn[0],ne=Qn[1],ee=Qn[2],re=Xn(.001),te=re[0],le=re[1],ie=re[2];function ae(n,e){return n.map((n=>n.map(((r,t)=>0==t||8==t||null==r?r:e(1==t||0==n[8]?r:n[1]+r)))))}function oe(n,e){return(r,t,l,i,a)=>{var o,s,u,f,c,v,h=e.find((n=>a>=n[0]))||e[e.length-1];return t.map((e=>{var r=n(e),t=r.getFullYear(),l=r.getMonth(),i=r.getDate(),a=r.getHours(),d=r.getMinutes(),m=r.getSeconds(),p=t!=o&&h[2]||l!=s&&h[3]||i!=u&&h[4]||a!=f&&h[5]||d!=c&&h[6]||m!=v&&h[7]||h[1];return o=t,s=l,u=i,f=a,c=d,v=m,p(r)}))}}function se(n,e,r){return new Date(n,e,r)}function ue(n,e){return e(n)}function fe(n,e){return(r,t)=>e(n(t))}L(2,-53,53,[1]);var ce={show:!0,width:2,stroke:function(n,e){var r=n.series[e];return r.width?r.stroke(n,e):r.points.width?r.points.stroke(n,e):null},fill:function(n,e){return n.series[e].fill(n,e)},dash:"solid",live:!0,isolate:!1,idx:null,values:[]},ve=[0,0];function he(n,e,r){return n=>{0==n.button&&r(n)}}function de(n,e,r){return r}var me={show:!0,x:!0,y:!0,lock:!1,move:function(n,e,r){return ve[0]=e,ve[1]=r,ve},points:{show:function(n,e){var r=n.cursor.points,t=wn(),l=r.stroke(n,e),i=r.fill(n,e);t.style.background=i||l;var a=r.size(n,e),o=r.width(n,e,a);o&&(t.style.border=o+"px solid "+l);var s=a/-2;return gn(t,Z,a),gn(t,K,a),gn(t,"marginLeft",s),gn(t,"marginTop",s),t},size:function(n,e){return Ye(n.series[e].width,1)},width:0,stroke:function(n,e){return n.series[e].stroke(n,e)},fill:function(n,e){return n.series[e].stroke(n,e)}},bind:{mousedown:he,mouseup:he,click:he,dblclick:he,mousemove:de,mouseleave:de,mouseenter:de},drag:{setScale:!0,x:!0,y:!1,dist:0,uni:null,_x:!1,_y:!1},focus:{prox:-1},left:-10,top:-10,idx:null,dataIdx:function(n,e,r){return r}},pe={show:!0,stroke:"rgba(0,0,0,0.07)",width:2,filter:P},ge=B({},pe,{size:10}),xe='12px system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans", sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol", "Noto Color Emoji"',we="bold "+xe,be={show:!0,scale:"x",stroke:en,space:50,gap:5,size:50,labelSize:30,labelFont:we,side:2,grid:pe,ticks:ge,font:xe,rotate:0},_e={show:!0,scale:"x",auto:!1,sorted:1,min:S,max:-S,idxs:[]};function ke(n,e){return e.map((n=>null==n?"":c(n)))}function ye(n,e,r,t,l,i,a){for(var o=[],s=F.get(l)||0,u=r=a?r:H(Y(r,l),s);t>=u;u=H(u+l,s))o.push(Object.is(u,-0)?0:u);return o}function Me(n,e,r,t,l){var i=[],a=n.scales[n.axes[e].scale].log,o=m((10==a?k:y)(r));l=b(a,o),0>o&&(l=H(l,-o));var s=r;do{i.push(s),l*a>(s=H(s+l,F.get(l)))||(l=s)}while(t>=s);return i}function Se(n,e,r,t,l){var i=n.scales[n.axes[e].scale].asinh,a=t>i?Me(n,e,w(i,r),t,l):[i],o=0>t||r>0?[]:[0];return(-i>r?Me(n,e,w(i,-t),-r,l):[i]).reverse().map((n=>-n)).concat(o,a)}var ze=/./,De=/[12357]/,Te=/[125]/,Ee=/1/;function Pe(n,e,r){var t=n.axes[r],l=t.scale,i=n.scales[l];if(3==i.distr&&2==i.log)return e;var a=n.valToPos,o=t._space,s=a(10,l),u=a(9,l)-s<o?a(7,l)-s<o?a(5,l)-s<o?Ee:Te:De:ze;return e.map((n=>4==i.distr&&0==n||u.test(n)?n:null))}function Ae(n,e){return null==e?"":c(e)}var We={show:!0,scale:"y",stroke:en,space:30,gap:5,size:50,labelSize:30,labelFont:we,side:3,grid:pe,ticks:ge,font:xe,rotate:0};function Ye(n,e){return H((3+2*(n||1))*e,3)}function Ce(n,e){var r=n.scales[n.series[e].scale],t=n.bands&&n.bands.some((n=>n.series[0]==e));return 3==r.distr||t?r.min:0}var He={scale:"y",auto:!0,sorted:0,show:!0,band:!1,spanGaps:!1,alpha:1,points:{show:function(n,e){var r=n.series[0].idxs;return(0==n.scales[n.series[0].scale].ori?n.bbox.width:n.bbox.height)/(n.series[e].points.space*dn)>=r[1]-r[0]}},values:null,min:S,max:-S,idxs:[],path:null,clip:null};function Fe(n,e,r){return r/10}var Re={time:!0,auto:!0,distr:1,log:10,asinh:1,min:null,max:null,dir:1,ori:0},Le=B({},Re,{time:!1,ori:1}),Ie={};function Ne(n){var e=Ie[n];if(!e){var r=[];e={key:n,sub:function(n){r.push(n)},unsub:function(n){r=r.filter((e=>e!=n))},pub:function(n,e,t,l,i,a){for(var o=0;r.length>o;o++)r[o]!=e&&r[o].pub(n,e,t,l,i,a,o)}},null!=n&&(Ie[n]=e)}return e}function Oe(n,e,r){var t=n.series[e],l=n.scales,i=n.bbox,a=n._data[0],o=n._data[e],s=l[n.series[0].scale],u=l[t.scale],f=i.left,c=i.top,v=i.width,h=i.height,d=n.valToPosH,m=n.valToPosV;return 0==s.ori?r(t,a,o,s,u,d,m,f,c,v,h,Be,qe,Ke,Qe,nr):r(t,a,o,s,u,m,d,c,f,h,v,Je,Ze,Xe,$e,er)}function Ve(n,e,r,t,l){return Oe(n,e,((n,e,i,a,o,s,u,f,c,v,h)=>{var d,m,p=0==a.ori?qe:Ze;1==a.dir*(0==a.ori?1:-1)?(d=r,m=t):(d=t,m=r);var g=z(s(e[d],a,v,f),.5),x=z(u(i[d],o,h,c),.5),w=z(s(e[m],a,v,f),.5),b=z(u(o.max,o,h,c),.5),_=new Path2D(l);return p(_,w,b),p(_,g,b),p(_,g,x),_}))}function je(n,e,r,t,l,i){var a=null;if(n.length>0){a=new Path2D;for(var o=0==e?Ke:Xe,s=r,u=0;n.length>u;u++){var f=n[u];o(a,s,t,f[0]-s,t+i),s=f[1]}o(a,s,t,r+l-s,t+i)}return a}function Ge(n,e,r){if(r>e){var t=n[n.length-1];t&&t[0]==e?t[1]=r:n.push([e,r])}}function Ue(n){return 0==n?E:1==n?p:e=>z(e,n)}function Be(n,e,r){n.moveTo(e,r)}function Je(n,e,r){n.moveTo(r,e)}function qe(n,e,r){n.lineTo(e,r)}function Ze(n,e,r){n.lineTo(r,e)}function Ke(n,e,r,t,l){n.rect(e,r,t,l)}function Xe(n,e,r,t,l){n.rect(r,e,l,t)}function Qe(n,e,r,t,l,i){n.arc(e,r,t,l,i)}function $e(n,e,r,t,l,i){n.arc(r,e,t,l,i)}function nr(n,e,r,t,l,i,a){n.bezierCurveTo(e,r,t,l,i,a)}function er(n,e,r,t,l,i,a){n.bezierCurveTo(r,e,l,t,a,i)}function rr(n){return(e,r,t,l,i,a)=>{t!=l&&(i!=t&&a!=t&&n(e,r,t),i!=l&&a!=l&&n(e,r,l),n(e,r,a))}}var tr=rr(qe),lr=rr(Ze);function ir(){return(n,r,t,l)=>Oe(n,r,((i,a,o,s,u,f,c,v,h,d,m)=>{var p,g,b=i.pxRound;0==s.ori?(p=qe,g=tr):(p=Ze,g=lr);var _,k,y,M,D=s.dir*(0==s.ori?1:-1),T={stroke:new Path2D,fill:null,clip:null,band:null},E=T.stroke,P=S,A=-S,W=[],Y=b(f(a[1==D?t:l],s,d,v)),C=!1,H=e(o,t,l,1*D),F=e(o,t,l,-1*D),R=z(f(a[H],s,d,v),.5),L=z(f(a[F],s,d,v),.5);R>v&&Ge(W,v,R);for(var I=1==D?t:l;I>=t&&l>=I;I+=D){var N=b(f(a[I],s,d,v));if(N==Y)null!=o[I]?(k=b(c(o[I],u,m,h)),P==S&&(p(E,N,k),_=k),P=x(k,P),A=w(k,A)):C||null!==o[I]||(C=!0);else{var O=!1;P!=S?(g(E,Y,P,A,_,k),y=M=Y):C&&(O=!0,C=!1),null!=o[I]?(p(E,N,k=b(c(o[I],u,m,h))),P=A=_=k,N-Y>1&&null===o[I-D]&&(O=!0)):(P=S,A=-S,C||null!==o[I]||(C=!0)),O&&Ge(W,y,N),Y=N}}if(P!=S&&P!=A&&M!=Y&&g(E,Y,P,A,_,k),v+d>L&&Ge(W,L,v+d),null!=i.fill){var V=T.fill=new Path2D(E),j=b(c(i.fillTo(n,r,i.min,i.max),u,m,h));p(V,L,j),p(V,R,j)}return i.spanGaps||(T.clip=je(W,s.ori,v,h,d,m)),n.bands.length>0&&(T.band=Ve(n,r,t,l,E)),T}))}function ar(n,e,r,t,l,i){var a,o,s,u,f,c,v,h,d,m,p,g,x,w,k,y,M,S,z,D,T,E,P,A,W,Y=new Path2D,C=n.length;t(Y,i(n[0]),i(e[0]));for(var H=0;C-1>H;H++){var F=0==H?0:H-1;o=e[F],u=e[H],f=n[H+1],c=e[H+1],C>H+2?(v=n[H+2],h=e[H+2]):(v=f,h=c),x=_(b((a=n[F])-(s=n[H]),2)+b(o-u,2)),w=_(b(s-f,2)+b(u-c,2)),k=_(b(f-v,2)+b(c-h,2)),D=b(k,r),E=b(k,2*r),T=b(w,r),P=b(w,2*r),(S=3*(W=b(x,r))*(W+T))>0&&(S=1/S),(z=3*D*(D+T))>0&&(z=1/z),m=(-P*o+(y=2*(A=b(x,2*r))+3*W*T+P)*u+A*c)*S,g=(E*u+(M=2*E+3*D*T+P)*c-P*h)*z,0==(d=(-P*a+y*s+A*f)*S)&&0==m&&(d=s,m=u),0==(p=(E*s+M*f-P*v)*z)&&0==g&&(p=f,g=c),l(Y,d,m,p,g,f,c)}return Y}var or=new Set;function sr(){or.forEach((n=>{n.syncRect(!0)}))}yn("resize",hn,sr),yn("scroll",hn,sr,!0);var ur=ir();function fr(n,e,r,t){return(t?[n[0],n[1]].concat(n.slice(2)):[n[0]].concat(n.slice(1))).map(((n,t)=>cr(n,t,e,r)))}function cr(n,e,r,t){return B({},0==e?r:t,n)}function vr(n,e,r){return null==e?N:[e,r]}var hr=vr;function dr(n,e,r){return null==e?N:s(e,r,.1,!0)}function mr(n,e,r,t){return null==e?N:l(e,r,n.scales[t].log,!1)}var pr=mr;function gr(n,e,r,t){return null==e?N:i(e,r,n.scales[t].log,!1)}var xr=gr;function wr(n){var e;return[n=n.replace(/(\d+)px/,((n,r)=>(e=p(r*dn))+"px")),e]}function br(e,r,t){var a={};function o(n,e){return((3==e.distr?k(n>0?n:e.clamp(a,n,e.min,e.max,e.key)):4==e.distr?M(n,e.asinh):n)-e._min)/(e._max-e._min)}function f(n,e,r,t){var l=o(n,e);return t+r*(-1==e.dir?1-l:l)}function c(n,e,r,t){var l=o(n,e);return t+r*(-1==e.dir?l:1-l)}function _(n,e,r,t){return 0==e.ori?f(n,e,r,t):c(n,e,r,t)}a.valToPosH=f,a.valToPosV=c;var y=!1;a.status=0;var E=a.root=wn("uplot");null!=e.id&&(E.id=e.id),mn(E,e.class),e.title&&(wn("u-title",E).textContent=e.title);var C=xn("canvas"),R=a.ctx=C.getContext("2d"),L=wn("u-wrap",E),J=wn("u-under",L);L.appendChild(C);var en=wn("u-over",L),hn=+u((e=U(e)).pxAlign,1),_n=Ue(hn);(e.plugins||[]).forEach((n=>{n.opts&&(e=n.opts(a,e)||e)}));var kn=e.ms||.001,Sn=a.series=fr(e.series||[],_e,He,!1),zn=a.axes=fr(e.axes||[],be,We,!0),Dn=a.scales={},Tn=a.bands=e.bands||[];Tn.forEach((n=>{n.fill=T(n.fill||null)}));var En=Sn[0].scale,Pn={axes:function(){zn.forEach(((n,e)=>{if(n.show&&n._show){var r,t,l=Dn[n.scale],i=n.side,o=i%2,s=0==o?er:rr,u=0==o?Xe:nr,f=p(n.gap*dn),c=n._found,v=c[0],d=c[1];if(n.label){R.save();var m=p(n._lpos*dn);1==o?(r=t=0,R.translate(m,p(nr+rr/2)),R.rotate((3==i?-h:h)/2)):(r=p(Xe+er/2),t=m),R.font=n.labelFont[0],R.textAlign="center",R.textBaseline=2==i?X:Q,R.fillText(n.label,r,t),R.restore()}if(0!=d){var g=n._splits,x=2==l.distr?g.map((n=>Fr[n])):g,w=2==l.distr?Fr[g[1]]-Fr[g[0]]:v,b=n.ticks,k=b.show?p(b.size*dn):0,y=n._rotate*-h/180,M=_n(n._pos*dn),S=M+(k+f)*(0==o&&0==i||1==o&&3==i?-1:1);t=0==o?S:0,r=1==o?S:0,R.font=n.font[0],R.fillStyle=n.stroke(a,e),R.textAlign=1==n.align?$:2==n.align?nn:y>0?$:0>y?nn:0==o?"center":3==i?nn:$,R.textBaseline=y||1==o?"middle":2==i?X:Q;var z=1.5*n.font[1],D=g.map((n=>_n(_(n,l,s,u))));n._values.forEach(((n,e)=>{null!=n&&(0==o?r=D[e]:t=D[e],(""+n).split(/\n/gm).forEach(((n,e)=>{y?(R.save(),R.translate(r,t+e*z),R.rotate(y),R.fillText(n,0,0),R.restore()):R.fillText(n,r,t+e*z)})))})),b.show&&Vr(D,b.filter(a,x,e,d,w),o,i,M,k,H(b.width*dn,3),b.stroke(a,e),b.dash,b.cap);var T=n.grid;T.show&&Vr(D,T.filter(a,x,e,d,w),o,0==o?2:1,0==o?nr:Xe,0==o?rr:er,H(T.width*dn,3),T.stroke(a,e),T.dash,T.cap)}}})),Nt("drawAxes")},series:function(){Pr>0&&(Sn.forEach(((n,e)=>{if(e>0&&n.show&&null==n._paths){var t=function(n){for(var e=D(Yr-1,0,Pr-1),r=D(Cr+1,0,Pr-1);null==n[e]&&e>0;)e--;for(;null==n[r]&&Pr-1>r;)r++;return[e,r]}(r[e]);n._paths=n.paths(a,e,t[0],t[1])}})),Sn.forEach(((n,e)=>{e>0&&n.show&&(n._paths&&function(n){var e=Sn[n],r=e._paths,t=r.stroke,l=r.fill,i=r.clip,o=H(e.width*dn,3),s=o%2/2,u=e._stroke=e.stroke(a,n),f=e._fill=e.fill(a,n);R.globalAlpha=e.alpha;var c=1==e.pxAlign;c&&R.translate(s,s),R.save();var v=Xe,h=nr,d=er,m=rr,p=o*dn/2;0==e.min&&(m+=p),0==e.max&&(h-=p,m+=p),R.beginPath(),R.rect(v,h,d,m),R.clip(),i&&R.clip(i),function(n,e,r,t,l,i,o,s){var u=!1;Tn.forEach(((f,c)=>{if(f.series[0]==n){var v=Sn[f.series[1]],h=(v._paths||I).band;R.save();var d=null;v.show&&h&&(d=f.fill(a,c)||i,R.clip(h)),Or(e,r,t,l,d,o,s),R.restore(),u=!0}})),u||Or(e,r,t,l,i,o,s)}(n,u,o,e.dash,e.cap,f,t,l),R.restore(),c&&R.translate(-s,-s),R.globalAlpha=1}(e),n.points.show(a,e,Yr,Cr)&&function(n){var e=Sn[n],t=e.points,l=e.pxRound,i=H(t.width*dn,3),o=i%2/2,s=t.width>0,u=(t.size-t.width)/2*dn,f=H(2*u,3),c=1==e.pxAlign;c&&R.translate(o,o),R.save(),R.beginPath(),R.rect(Xe-f,nr-f,er+2*f,rr+2*f),R.clip(),R.globalAlpha=e.alpha;var v,d,m,p,g=new Path2D,x=Dn[e.scale];0==On.ori?(v=er,d=Xe,m=rr,p=nr):(v=rr,d=nr,m=er,p=Xe);for(var w=Yr;Cr>=w;w++)if(null!=r[n][w]){var b=l(Hn(r[0][w],On,v,d)),_=l(Fn(r[n][w],x,m,p));Rn(g,b+u,_),Ln(g,b,_,u,0,2*h)}var k=t._stroke=t.stroke(a,n),y=t._fill=t.fill(a,n);Nr(k,i,t.dash,t.cap,y||(s?"#fff":e._stroke)),R.fill(g),s&&R.stroke(g),R.globalAlpha=1,R.restore(),c&&R.translate(-o,-o)}(e),Nt("drawSeries",e))})))}},An=(e.drawOrder||["axes","series"]).map((n=>Pn[n]));function Wn(n){var r=Dn[n];if(null==r){var t=(e.scales||I)[n]||I;if(null!=t.from)Wn(t.from),Dn[n]=B({},Dn[t.from],t);else{(r=Dn[n]=B({},n==En?Re:Le,t)).key=n;var l=r.time,i=r.range,a=O(i);if(n!=En&&!a&&j(i)){var o=i;i=(n,e,r)=>null==e?N:s(e,r,o)}r.range=T(i||(l?hr:n==En?3==r.distr?pr:4==r.distr?xr:vr:3==r.distr?mr:4==r.distr?gr:dr)),r.auto=T(!a&&r.auto),r.clamp=T(r.clamp||Fe),r._min=r._max=null}}}for(var Cn in Wn("x"),Wn("y"),Sn.forEach((n=>{Wn(n.scale)})),zn.forEach((n=>{Wn(n.scale)})),e.scales)Wn(Cn);var Hn,Fn,Rn,Ln,On=Dn[En],Vn=On.distr;0==On.ori?(mn(E,"u-hz"),Hn=f,Fn=c,Rn=Be,Ln=Qe):(mn(E,"u-vt"),Hn=c,Fn=f,Rn=Je,Ln=$e);var jn={};for(var Gn in Dn){var Un=Dn[Gn];null==Un.min&&null==Un.max||(jn[Gn]={min:Un.min,max:Un.max},Un.min=Un.max=null)}var Bn,Jn=e.tzDate||(n=>new Date(p(n/kn))),qn=e.fmtDate||Yn,Zn=1==kn?ee(Jn):ie(Jn),Kn=oe(Jn,ae(1==kn?ne:le,qn)),Xn=fe(Jn,ue("{YYYY}-{MM}-{DD} {h}:{mm}{aa}",qn)),Qn=a.legend=B({},ce,e.legend),re=Qn.show;Qn.width=T(Qn.width),Qn.dash=T(Qn.dash),Qn.stroke=T(Qn.stroke),Qn.fill=T(Qn.fill);var se,ve=[],he=[],de=!1,pe={};if(Qn.live){var ge=Sn[1]?Sn[1].values:null;for(var xe in se=(de=null!=ge)?ge(a,1,0):{_:0})pe[xe]="--"}if(re)if(Bn=xn("table","u-legend",E),de){var we=xn("tr","u-thead",Bn);for(var ze in xn("th",null,we),se)xn("th",cn,we).textContent=ze}else mn(Bn,"u-inline"),Qn.live&&mn(Bn,"u-live");var De={show:!0},Te={show:!1},Ee=new Map;function Ie(n,e,r){var t=Ee.get(e)||{},l=kr.bind[n](a,e,r);l&&(yn(n,e,t[n]=l),Ee.set(e,t))}function Oe(n,e){var r=Ee.get(e)||{};for(var t in r)null!=n&&t!=n||(Mn(t,e,r[t]),delete r[t]);null==n&&Ee.delete(e)}var Ve=0,je=0,Ge=0,qe=0,Ze=0,Ke=0,Xe=0,nr=0,er=0,rr=0;a.bbox={};var tr=!1,lr=!1,ir=!1,ar=!1,sr=!1;function br(n,e){n==a.width&&e==a.height||_r(n,e),Ur(!1),ir=!0,lr=!0,ar=kr.left>=0,sr=!0,it()}function _r(n,e){a.width=Ve=Ge=n,a.height=je=qe=e,Ze=Ke=0,function(){var n=!1,e=!1,r=!1,t=!1;zn.forEach((l=>{if(l.show&&l._show){var i=l.side,a=i%2,o=l._size+(l.labelSize=null!=l.label?l.labelSize||30:0);o>0&&(a?(Ge-=o,3==i?(Ze+=o,t=!0):r=!0):(qe-=o,0==i?(Ke+=o,n=!0):e=!0))}})),Tr[0]=n,Tr[1]=r,Tr[2]=e,Tr[3]=t,Ge-=Wr[1]+Wr[3],Ze+=Wr[3],qe-=Wr[2]+Wr[0],Ke+=Wr[0]}(),function(){var n=Ze+Ge,e=Ke+qe,r=Ze,t=Ke;function l(l,i){switch(l){case 1:return(n+=i)-i;case 2:return(e+=i)-i;case 3:return(r-=i)+i;case 0:return(t-=i)+i}}zn.forEach((n=>{if(n.show&&n._show){var e=n.side;n._pos=l(e,n._size),null!=n.label&&(n._lpos=l(e,n.labelSize))}}))}();var r=a.bbox;Xe=r.left=z(Ze*dn,.5),nr=r.top=z(Ke*dn,.5),er=r.width=z(Ge*dn,.5),rr=r.height=z(qe*dn,.5)}a.setSize=function(n){br(n.width,n.height)};var kr=a.cursor=B({},me,e.cursor);kr._lock=!1;var yr=kr.points;yr.show=T(yr.show),yr.size=T(yr.size),yr.stroke=T(yr.stroke),yr.width=T(yr.width),yr.fill=T(yr.fill);var Mr=a.focus=B({},e.focus||{alpha:.3},kr.focus),Sr=Mr.prox>=0,zr=[null];function Dr(n,e){var r=Dn[n.scale].time,t=n.value;if(n.value=r?V(t)?fe(Jn,ue(t,qn)):t||Xn:t||Ae,n.label=n.label||(r?"Time":"Value"),e>0){n.width=null==n.width?1:n.width,n.paths=n.paths||ur||A,n.fillTo=T(n.fillTo||Ce),n.pxAlign=+u(n.pxAlign,hn),n.pxRound=Ue(n.pxAlign),n.stroke=T(n.stroke||null),n.fill=T(n.fill||null),n._stroke=n._fill=n._paths=n._focus=null;var l=Ye(n.width,1),i=n.points=B({},{size:l,width:w(1,.2*l),stroke:n.stroke,space:2*l,_stroke:null,_fill:null},n.points);i.show=T(i.show),i.fill=T(i.fill),i.stroke=T(i.stroke)}if(re){var o=function(n,e){if(0==e&&(de||!Qn.live))return N;var r=[],t=xn("tr","u-series",Bn,Bn.childNodes[e]);mn(t,n.class),n.show||mn(t,fn);var l=xn("th",null,t),i=wn("u-marker",l);if(e>0){var o=Qn.width(a,e);o&&(i.style.border=o+"px "+Qn.dash(a,e)+" "+Qn.stroke(a,e)),i.style.background=Qn.fill(a,e)}var s=wn(cn,l);for(var u in s.textContent=n.label,e>0&&(Ie("click",l,(e=>{if(!kr._lock){var r=Sn.indexOf(n);if(e.ctrlKey!=Qn.isolate){var t=Sn.some(((n,e)=>e>0&&e!=r&&n.show));Sn.forEach(((n,e)=>{e>0&&wt(e,t?e==r?De:Te:De,Ot.setSeries)}))}else wt(r,{show:!n.show},Ot.setSeries)}})),Sr&&Ie(on,l,(()=>{kr._lock||wt(Sn.indexOf(n),bt,Ot.setSeries)}))),se){var f=xn("td","u-value",t);f.textContent="--",r.push(f)}return[t,r]}(n,e);ve.splice(e,0,o[0]),he.splice(e,0,o[1]),Qn.values.push(null)}if(kr.show){var s=function(n,e){if(e>0){var r=kr.points.show(a,e);if(r)return mn(r,"u-cursor-pt"),mn(r,n.class),bn(r,-10,-10,Ge,qe),en.insertBefore(r,zr[e]),r}}(n,e);s&&zr.splice(e,0,s)}}a.addSeries=function(n,e){n=cr(n,e=null==e?Sn.length:e,_e,He),Sn.splice(e,0,n),Dr(Sn[e],e)},a.delSeries=function(n){if(Sn.splice(n,1),re){Qn.values.splice(n,1),he.splice(n,1);var e=ve.splice(n,1)[0];Oe(null,e.firstChild),e.remove()}zr.length>1&&zr.splice(n,1)[0].remove()};var Tr=[!1,!1,!1,!1];function Er(n,e,r){var t=r[0],l=r[1],i=r[2],a=r[3],o=e%2,s=0;return 0==o&&(a||l)&&(s=0==e&&!t||2==e&&!i?p(be.size/3):0),1==o&&(t||i)&&(s=1==e&&!l||3==e&&!a?p(We.size/2):0),s}var Pr,Ar=a.padding=(e.padding||[Er,Er,Er,Er]).map((n=>T(u(n,Er)))),Wr=a._padding=Ar.map(((n,e)=>n(a,e,Tr,0))),Yr=null,Cr=null,Hr=Sn[0].idxs,Fr=null,Rr=!1;function Lr(n,e){if((r=(n||[]).slice())[0]=r[0]||[],a.data=r.slice(),Pr=(Fr=r[0]).length,2==Vn&&(r[0]=Fr.map(((n,e)=>e))),a._data=r,Ur(!0),Nt("setData"),!1!==e){var t=On;t.auto(a,Rr)?Ir():xt(En,t.min,t.max),ar=kr.left>=0,sr=!0,it()}}function Ir(){var n,e,t,a,o;Rr=!0,Pr>0?(Yr=Hr[0]=0,Cr=Hr[1]=Pr-1,a=r[0][Yr],o=r[0][Cr],2==Vn?(a=Yr,o=Cr):1==Pr&&(3==Vn?(a=(n=l(a,a,On.log,!1))[0],o=n[1]):4==Vn?(a=(e=i(a,a,On.log,!1))[0],o=e[1]):On.time?o=a+p(86400/kn):(a=(t=s(a,o,.1,!0))[0],o=t[1]))):(Yr=Hr[0]=a=null,Cr=Hr[1]=o=null),xt(En,a,o)}function Nr(n,e,r,t,l){R.strokeStyle=n||rn,R.lineWidth=e,R.lineJoin="round",R.lineCap=t||"butt",R.setLineDash(r||[]),R.fillStyle=l||rn}function Or(n,e,r,t,l,i,a){Nr(n,e,r,t,l),l&&a&&R.fill(a),n&&i&&e&&R.stroke(i)}function Vr(n,e,r,t,l,i,a,o,s,u){var f=a%2/2;1==hn&&R.translate(f,f),Nr(o,a,s,u),R.beginPath();var c,v,h,d,m=l+(0==t||3==t?-i:i);0==r?(v=l,d=m):(c=l,h=m),n.forEach(((n,t)=>{null!=e[t]&&(0==r?c=h=n:v=d=n,R.moveTo(c,v),R.lineTo(h,d))})),R.stroke(),1==hn&&R.translate(-f,-f)}function jr(n){var e=!0;return zn.forEach(((r,t)=>{if(r.show){var l=Dn[r.scale];if(null!=l.min){r._show||(e=!1,r._show=!0,Ur(!1));var i=r.side,o=l.min,s=l.max,u=function(n,e,r,t){var l,i=zn[n];if(t>0){var o=i._space=i.space(a,n,e,r,t),s=i._incrs=i.incrs(a,n,e,r,t,o);l=i._found=function(n,e,r,t,l){for(var i=t/(e-n),a=(""+m(n)).length,o=0;r.length>o;o++){var s=r[o]*i,u=10>r[o]?F.get(r[o]):0;if(s>=l&&17>a+u)return[r[o],s]}return[0,0]}(e,r,s,t,o)}else l=[0,0];return l}(t,o,s,0==i%2?Ge:qe),f=u[0],c=u[1];if(0!=c){var v=r._splits=r.splits(a,t,o,s,f,c,2==l.distr),h=2==l.distr?v.map((n=>Fr[n])):v,d=2==l.distr?Fr[v[1]]-Fr[v[0]]:f,p=r._values=r.values(a,r.filter(a,h,t,c,d),t,c,d);r._rotate=2==i?r.rotate(a,p,t,c):0;var x=r._size;r._size=g(r.size(a,p,t,n)),null!=x&&r._size!=x&&(e=!1)}}else r._show&&(e=!1,r._show=!1,Ur(!1))}})),e}function Gr(n){var e=!0;return Ar.forEach(((r,t)=>{var l=r(a,t,Tr,n);l!=Wr[t]&&(e=!1),Wr[t]=l})),e}function Ur(n){Sn.forEach(((e,r)=>{r>0&&(e._paths=null,n&&(e.min=null,e.max=null))}))}a.setData=Lr;var Br,Jr,qr,Zr,Kr,Xr,Qr,$r,nt,et,rt,tt,lt=!1;function it(){lt||(q(at),lt=!0)}function at(){tr&&(function(){var e=U(Dn,G);for(var t in e){var l=e[t],i=jn[t];if(null!=i&&null!=i.min)B(l,i),t==En&&Ur(!0);else if(t!=En)if(0==Pr&&null==l.from){var o=l.range(a,null,null,t);l.min=o[0],l.max=o[1]}else l.min=S,l.max=-S}if(Pr>0)for(var s in Sn.forEach(((t,l)=>{var i=t.scale,o=e[i],s=jn[i];if(0==l){var u=o.range(a,o.min,o.max,i);o.min=u[0],o.max=u[1],Yr=n(o.min,r[0]),Cr=n(o.max,r[0]),o.min>r[0][Yr]&&Yr++,r[0][Cr]>o.max&&Cr--,t.min=Fr[Yr],t.max=Fr[Cr]}else if(t.show&&t.auto&&o.auto(a,Rr)&&(null==s||null==s.min)){var f=null==t.min?3==o.distr?function(n,e,r){for(var t=S,l=-S,i=e;r>=i;i++)n[i]>0&&(t=x(t,n[i]),l=w(l,n[i]));return[t==S?1:t,l==-S?10:l]}(r[l],Yr,Cr):function(n,e,r,t){var l=S,i=-S;if(1==t)l=n[e],i=n[r];else if(-1==t)l=n[r],i=n[e];else for(var a=e;r>=a;a++)null!=n[a]&&(l=x(l,n[a]),i=w(i,n[a]));return[l,i]}(r[l],Yr,Cr,t.sorted):[t.min,t.max];o.min=x(o.min,t.min=f[0]),o.max=w(o.max,t.max=f[1])}t.idxs[0]=Yr,t.idxs[1]=Cr})),e){var u=e[s],f=jn[s];if(null==u.from&&(null==f||null==f.min)){var c=u.range(a,u.min==S?null:u.min,u.max==-S?null:u.max,s);u.min=c[0],u.max=c[1]}}for(var v in e){var h=e[v];if(null!=h.from){var d=e[h.from],m=h.range(a,d.min,d.max,v);h.min=m[0],h.max=m[1]}}var p={},g=!1;for(var b in e){var _=e[b],y=Dn[b];if(y.min!=_.min||y.max!=_.max){y.min=_.min,y.max=_.max;var z=y.distr;y._min=3==z?k(y.min):4==z?M(y.min,y.asinh):y.min,y._max=3==z?k(y.max):4==z?M(y.max,y.asinh):y.max,p[b]=g=!0}}if(g){for(var D in Sn.forEach((n=>{p[n.scale]&&(n._paths=null)})),p)ir=!0,Nt("setScale",D);kr.show&&(ar=kr.left>=0)}for(var T in jn)jn[T]=null}(),tr=!1),ir&&(function(){for(var n=!1,e=0;!n;){var r=jr(++e),t=Gr(e);(n=r&&t)||(_r(a.width,a.height),lr=!0)}}(),ir=!1),lr&&(gn(J,$,Ze),gn(J,X,Ke),gn(J,Z,Ge),gn(J,K,qe),gn(en,$,Ze),gn(en,X,Ke),gn(en,Z,Ge),gn(en,K,qe),gn(L,Z,Ve),gn(L,K,je),C.width=p(Ve*dn),C.height=p(je*dn),At(!1),Nt("setSize"),lr=!1),Ve>0&&je>0&&(R.clearRect(0,0,C.width,C.height),Nt("drawClear"),An.forEach((n=>n())),Nt("draw")),kr.show&&ar&&(Et(),ar=!1),y||(y=!0,a.status=1,Nt("ready")),Rr=!1,lt=!1}function ot(e,t){var l=Dn[e];if(null==l.from){if(0==Pr){var i=l.range(a,t.min,t.max,e);t.min=i[0],t.max=i[1]}if(t.min>t.max){var o=t.min;t.min=t.max,t.max=o}if(Pr>1&&null!=t.min&&null!=t.max&&1e-16>t.max-t.min)return;e==En&&2==l.distr&&Pr>0&&(t.min=n(t.min,r[0]),t.max=n(t.max,r[0])),jn[e]=t,tr=!0,it()}}a.redraw=(n,e)=>{ir=e||!1,!1!==n?xt(En,On.min,On.max):it()},a.setScale=ot;var st=!1,ut=kr.drag,ft=ut.x,ct=ut.y;kr.show&&(kr.x&&(Br=wn("u-cursor-x",en)),kr.y&&(Jr=wn("u-cursor-y",en)),0==On.ori?(qr=Br,Zr=Jr):(qr=Jr,Zr=Br),rt=kr.left,tt=kr.top);var vt,ht,dt,mt=a.select=B({show:!0,over:!0,left:0,width:0,top:0,height:0},e.select),pt=mt.show?wn("u-select",mt.over?en:J):null;function gt(n,e){if(mt.show){for(var r in n)gn(pt,r,mt[r]=n[r]);!1!==e&&Nt("setSelect")}}function xt(n,e,r){ot(n,{min:e,max:r})}function wt(n,e,r){var t=Sn[n];null!=e.focus&&function(n){if(n!=dt){var e=null==n,r=1!=Mr.alpha;Sn.forEach(((t,l)=>{var i=e||0==l||l==n;t._focus=e?null:i,r&&function(n,e){Sn[n].alpha=e,kr.show&&zr[n]&&(zr[n].style.opacity=e),re&&ve[n]&&(ve[n].style.opacity=e)}(l,i?1:Mr.alpha)})),dt=n,r&&it()}}(n),null!=e.show&&(t.show=e.show,function(n){var e=re?ve[n]:null;Sn[n].show?e&&pn(e,fn):(e&&mn(e,fn),zr.length>1&&bn(zr[n],-10,-10,Ge,qe))}(n),xt(t.scale,null,null),it()),Nt("setSeries",n,e),r&&jt("setSeries",a,n,e)}a.setSelect=gt,a.setSeries=wt;var bt={focus:!0},_t={focus:!1};function kt(n,e){var r=Dn[e],t=Ge;1==r.ori&&(n=(t=qe)-n),-1==r.dir&&(n=t-n);var l=r._min,i=l+n/t*(r._max-l),a=r.distr;return 3==a?b(10,i):4==a?((n,e)=>(void 0===e&&(e=1),v.sinh(n/e)))(i,r.asinh):i}function yt(n,e){gn(pt,$,mt.left=n),gn(pt,Z,mt.width=e)}function Mt(n,e){gn(pt,X,mt.top=n),gn(pt,K,mt.height=e)}re&&Sr&&yn(sn,Bn,(()=>{kr._lock||(wt(null,_t,Ot.setSeries),Et())})),a.valToIdx=e=>n(e,r[0]),a.posToIdx=function(e){return n(kt(e,En),r[0],Yr,Cr)},a.posToVal=kt,a.valToPos=(n,e,r)=>0==Dn[e].ori?f(n,Dn[e],r?er:Ge,r?Xe:0):c(n,Dn[e],r?rr:qe,r?nr:0),a.batch=function(n){n(a),it()},a.setCursor=n=>{rt=n.left,tt=n.top,Et()};var St=0==On.ori?yt:Mt,zt=1==On.ori?yt:Mt;function Dt(n,e){if(null!=n){var r=n.idx;Qn.idx=r,Sn.forEach(((n,e)=>{(e>0||!de)&&Tt(e,r)}))}re&&Qn.live&&function(){if(re&&Qn.live)for(var n=0;Sn.length>n;n++)if(0!=n||!de){var e=Qn.values[n],r=0;for(var t in e)he[n][r++].firstChild.nodeValue=e[t]}}(),sr=!1,!1!==e&&Nt("setLegend")}function Tt(n,e){var t;if(null==e)t=pe;else{var l=Sn[n],i=0==n&&2==Vn?Fr:r[n];t=de?l.values(a,n,e):{_:l.value(a,i[e],n,e)}}Qn.values[n]=t}function Et(e,t){var l,i;nt=rt,et=tt,l=kr.move(a,rt,tt),rt=l[0],tt=l[1],kr.show&&(qr&&bn(qr,p(rt),0,Ge,qe),Zr&&bn(Zr,0,p(tt),Ge,qe));var o=!1;vt=S;var s=0==On.ori?Ge:qe,u=1==On.ori?Ge:qe;if(0>rt||0==Pr||Yr>Cr){i=null;for(var f=0;Sn.length>f;f++)f>0&&zr.length>1&&bn(zr[f],-10,-10,Ge,qe);if(Sr&&wt(null,bt,Ot.setSeries),Qn.live){o=!0;for(var c=0;Sn.length>c;c++)Qn.values[c]=pe}}else{var v=kt(0==On.ori?rt:tt,En);i=n(v,r[0],Yr,Cr);for(var h=Y(Hn(r[0][i],On,s,0),.5),m=0;Sn.length>m;m++){var g=Sn[m],w=kr.dataIdx(a,m,i,v),b=w==i?h:Y(Hn(r[0][w],On,s,0),.5);if(m>0&&g.show){var _=r[m][w],k=null==_?-10:Y(Fn(_,Dn[g.scale],u,0),.5);if(k>0){var M=d(k-tt);M>vt||(vt=M,ht=m)}var z=void 0,D=void 0;0==On.ori?(z=b,D=k):(z=k,D=b),zr.length>1&&bn(zr[m],z,D,Ge,qe)}if(Qn.live){if(w==kr.idx&&!sr||0==m&&de)continue;o=!0,Tt(m,w)}}}if(o&&(Qn.idx=i,Dt()),mt.show&&st)if(null!=t){var T=Ot.scales,E=T[0],P=T[1],A=t.cursor.drag;ft=A._x,ct=A._y;var W,C,H,F,R,L=t.select,I=L.left,N=L.top,O=L.width,V=L.height,j=t.scales[E].ori,G=t.posToVal;E&&(0==j?(W=I,C=O):(W=N,C=V),H=Dn[E],F=Hn(G(W,E),H,s,0),R=Hn(G(W+C,E),H,s,0),St(x(F,R),d(R-F)),P||zt(0,u)),P&&(1==j?(W=I,C=O):(W=N,C=V),H=Dn[P],F=Fn(G(W,P),H,u,0),R=Fn(G(W+C,P),H,u,0),zt(x(F,R),d(R-F)),E||St(0,s))}else{var U=d(nt-Kr),B=d(et-Xr);if(1==On.ori){var J=U;U=B,B=J}ft=ut.x&&U>=ut.dist,ct=ut.y&&B>=ut.dist;var q,Z,K=ut.uni;null!=K?ft&&ct&&(ct=B>=K,(ft=U>=K)||ct||(B>U?ct=!0:ft=!0)):ut.x&&ut.y&&(ft||ct)&&(ft=ct=!0),ft&&(0==On.ori?(q=Qr,Z=rt):(q=$r,Z=tt),St(x(q,Z),d(Z-q)),ct||zt(0,u)),ct&&(1==On.ori?(q=Qr,Z=rt):(q=$r,Z=tt),zt(x(q,Z),d(Z-q)),ft||St(0,s)),ft||ct||(St(0,0),zt(0,0))}if(kr.idx=i,kr.left=rt,kr.top=tt,ut._x=ft,ut._y=ct,null!=e&&(jt(tn,a,rt,tt,s,u,i),Sr)){var X=Ot.setSeries,Q=Mr.prox;null==dt?vt>Q||wt(ht,bt,X):vt>Q?wt(null,bt,X):ht!=dt&&wt(ht,bt,X)}y&&Nt("setCursor")}a.setLegend=Dt;var Pt=null;function At(n){Pt=n?null:en.getBoundingClientRect()}function Wt(n,e,r,t,l,i){kr._lock||(Yt(n,e,r,t,l,i,0,!1,null!=n),null!=n?Et(1):Et(null,e))}function Yt(n,e,r,t,l,i,o,s,u){var f;if(null==Pt&&At(!1),null!=n)r=n.clientX-Pt.left,t=n.clientY-Pt.top;else{if(0>r||0>t)return rt=-10,void(tt=-10);var c=Ge,v=qe,h=l,d=i,m=r,p=t;1==On.ori&&(c=qe,v=Ge);var g=Ot.scales,x=g[0],w=g[1];if(1==e.scales[x].ori&&(h=i,d=l,m=t,p=r),r=null!=x?_(e.posToVal(m,x),Dn[x],c,0):c*(m/h),t=null!=w?_(e.posToVal(p,w),Dn[w],v,0):v*(p/d),1==On.ori){var b=r;r=t,t=b}}u&&(r>1&&Ge-1>r||(r=z(r,Ge)),t>1&&qe-1>t||(t=z(t,qe))),s?(Kr=r,Xr=t,f=kr.move(a,r,t),Qr=f[0],$r=f[1]):(rt=r,tt=t)}function Ct(){gt({width:0,height:0},!1)}function Ht(n,e,r,t,l,i){st=!0,ft=ct=ut._x=ut._y=!1,Yt(n,e,r,t,l,i,0,!0,!1),null!=n&&(Ie(an,vn,Ft),jt(ln,a,Qr,$r,Ge,qe,null))}function Ft(n,e,r,t,l,i){st=ut._x=ut._y=!1,Yt(n,e,r,t,l,i,0,!1,!0);var o=mt.left,s=mt.top,u=mt.width,f=mt.height,c=u>0||f>0;if(c&&gt(mt),ut.setScale&&c){var v=o,h=u,d=s,m=f;if(1==On.ori&&(v=s,h=f,d=o,m=u),ft&&xt(En,kt(v,En),kt(v+h,En)),ct)for(var p in Dn){var g=Dn[p];p!=En&&null==g.from&&g.min!=S&&xt(p,kt(d+m,p),kt(d,p))}Ct()}else kr.lock&&(kr._lock=!kr._lock,kr._lock||Et());null!=n&&(Oe(an,vn),jt(an,a,rt,tt,Ge,qe,null))}function Rt(n){Ir(),Ct(),null!=n&&jt(un,a,rt,tt,Ge,qe,null)}var Lt={};Lt.mousedown=Ht,Lt.mousemove=Wt,Lt.mouseup=Ft,Lt.dblclick=Rt,Lt.setSeries=(n,e,r,t)=>{wt(r,t)},kr.show&&(Ie(ln,en,Ht),Ie(tn,en,Wt),Ie(on,en,At),Ie(sn,en,(function(){if(!kr._lock){var n=st;if(st){var e,r,t=!0,l=!0;0==On.ori?(e=ft,r=ct):(e=ct,r=ft),e&&r&&(t=10>=rt||rt>=Ge-10,l=10>=tt||tt>=qe-10),e&&t&&(rt=Qr>rt?0:Ge),r&&l&&(tt=$r>tt?0:qe),Et(1),st=!1}rt=-10,tt=-10,Et(1),n&&(st=n)}})),Ie(un,en,Rt),or.add(a),a.syncRect=At);var It=a.hooks=e.hooks||{};function Nt(n,e,r){n in It&&It[n].forEach((n=>{n.call(null,a,e,r)}))}(e.plugins||[]).forEach((n=>{for(var e in n.hooks)It[e]=(It[e]||[]).concat(n.hooks[e])}));var Ot=B({key:null,setSeries:!1,filters:{pub:W,sub:W},scales:[En,null]},kr.sync),Vt=Ne(Ot.key);function jt(n,e,r,t,l,i,a){Ot.filters.pub(n,e,r,t,l,i,a)&&Vt.pub(n,e,r,t,l,i,a)}function Gt(){Nt("init",e,r),Lr(r||e.data,!1),jn[En]?ot(En,jn[En]):Ir(),br(e.width,e.height),Et(),gt(mt,!1)}return Vt.sub(a),a.pub=function(n,e,r,t,l,i,a){Ot.filters.sub(n,e,r,t,l,i,a)&&Lt[n](null,e,r,t,l,i,a)},a.destroy=function(){Vt.unsub(a),or.delete(a),Ee.clear(),E.remove(),Nt("destroy")},Sn.forEach(Dr),zn.forEach((function(n,e){if(n._show=n.show,n.show){var r=Dn[n.scale];null==r&&(n.scale=n.side%2?Sn[1].scale:En,r=Dn[n.scale]);var t=r.time;n.size=T(n.size),n.space=T(n.space),n.rotate=T(n.rotate),n.incrs=T(n.incrs||(2==r.distr?In:t?1==kn?$n:te:Nn)),n.splits=T(n.splits||(t&&1==r.distr?Zn:3==r.distr?Me:4==r.distr?Se:ye)),n.stroke=T(n.stroke),n.grid.stroke=T(n.grid.stroke),n.ticks.stroke=T(n.ticks.stroke);var l=n.values;n.values=O(l)&&!O(l[0])?T(l):t?O(l)?oe(Jn,ae(l,qn)):V(l)?function(n,e){var r=Yn(e);return(e,t)=>t.map((e=>r(n(e))))}(Jn,l):l||Kn:l||ke,n.filter=T(n.filter||(3>r.distr?P:Pe)),n.font=wr(n.font),n.labelFont=wr(n.labelFont),n._size=n.size(a,null,e,0),n._space=n._rotate=n._incrs=n._found=n._splits=n._values=null,n._size>0&&(Tr[e]=!0)}})),t?t instanceof HTMLElement?(t.appendChild(E),Gt()):t(a,Gt):Gt(),a}br.assign=B,br.fmtNum=c,br.rangeNum=s,br.rangeLog=l,br.rangeAsinh=i,br.orient=Oe,br.join=function(n,e){for(var r=new Set,t=0;n.length>t;t++)for(var l=n[t][0],i=l.length,a=0;i>a;a++)r.add(l[a]);for(var o=[Array.from(r).sort(((n,e)=>n-e))],s=o[0].length,u=new Map,f=0;s>f;f++)u.set(o[0][f],f);for(var c=0;n.length>c;c++)for(var v=n[c],h=v[0],d=1;v.length>d;d++){for(var m=v[d],p=Array(s).fill(void 0),g=e?e[c][d]:1,x=[],w=0;m.length>w;w++){var b=m[w],_=u.get(h[w]);null==b?0!=g&&(p[_]=b,2==g&&x.push(_)):p[_]=b}J(p,x,s),o.push(p)}return o},br.fmtDate=Yn,br.tzDate=function(n,e){var r;return"UTC"==e||"Etc/UTC"==e?r=new Date(+n+6e4*n.getTimezoneOffset()):e==Cn?r=n:(r=new Date(n.toLocaleString("en-US",{timeZone:e}))).setMilliseconds(n.getMilliseconds()),r},br.sync=Ne,br.addGap=Ge,br.clipGaps=je;var _r=br.paths={};return _r.linear=ir,_r.spline=function(){return(n,r,t,l)=>Oe(n,r,((i,a,o,s,u,f,c,v,h,d,m)=>{var p,g,x,w=i.pxRound;0==s.ori?(p=Be,x=qe,g=nr):(p=Je,x=Ze,g=er);var b=1*s.dir*(0==s.ori?1:-1);t=e(o,t,l,1),l=e(o,t,l,-1);for(var _=[],k=!1,y=w(f(a[1==b?t:l],s,d,v)),M=y,S=[],z=[],D=1==b?t:l;D>=t&&l>=D;D+=b){var T=o[D],E=f(a[D],s,d,v);null!=T?(k&&(Ge(_,M,E),k=!1),S.push(M=E),z.push(c(o[D],u,m,h))):null===T&&(Ge(_,M,E),k=!0)}var P={stroke:ar(S,z,.5,p,g,w),fill:null,clip:null,band:null},A=P.stroke;if(null!=i.fill){var W=P.fill=new Path2D(A),Y=w(c(i.fillTo(n,r,i.min,i.max),u,m,h));x(W,M,Y),x(W,y,Y)}return i.spanGaps||(P.clip=je(_,s.ori,v,h,d,m)),n.bands.length>0&&(P.band=Ve(n,r,t,l,A)),P}))},_r.stepped=function(n){var r=u(n.align,1),t=u(n.ascDesc,!1);return(n,l,i,a)=>Oe(n,l,((o,s,u,f,c,v,h,d,m,p,g)=>{var x=o.pxRound,w=0==f.ori?qe:Ze,b={stroke:new Path2D,fill:null,clip:null,band:null},_=b.stroke,k=1*f.dir*(0==f.ori?1:-1);i=e(u,i,a,1),a=e(u,i,a,-1);var y=[],M=!1,S=x(h(u[1==k?i:a],c,g,m)),z=x(v(s[1==k?i:a],f,p,d)),D=z;w(_,z,S);for(var T=1==k?i:a;T>=i&&a>=T;T+=k){var E=u[T],P=x(v(s[T],f,p,d));if(null!=E){var A=x(h(E,c,g,m));if(M){if(Ge(y,D,P),S!=A){var W=o.width*dn/2,Y=y[y.length-1];Y[0]+=t||1==r?W:-W,Y[1]-=t||-1==r?W:-W}M=!1}1==r?w(_,P,S):w(_,D,A),w(_,P,A),S=A,D=P}else null===E&&(Ge(y,D,P),M=!0)}if(null!=o.fill){var C=b.fill=new Path2D(_),H=x(h(o.fillTo(n,l,o.min,o.max),c,g,m));w(C,D,H),w(C,z,H)}return o.spanGaps||(b.clip=je(y,f.ori,d,m,p,g)),n.bands.length>0&&(b.band=Ve(n,l,i,a,_)),b}))},_r.bars=function(n){var r=u((n=n||I).size,[.6,S]),t=n.align||0,l=1-r[0],i=u(r[1],S)*dn;return(n,r,a,o)=>Oe(n,r,((s,u,f,c,v,h,d,m,p,g,b)=>{var _,k=s.pxRound,y=0==c.ori?Ke:Xe,M=h(u[1],c,g,m)-h(u[0],c,g,m),S=M*l,D=d(s.fillTo(n,r,s.min,s.max),v,b,p),T=k(s.width*dn),E=k(x(i,M-S)-T),P=1==t?0:-1==t?E:E/2,A={stroke:new Path2D,fill:null,clip:null,band:null},W=n.bands.length>0;W&&(A.band=new Path2D,_=z(d(v.max,v,b,p),.5));for(var Y=A.stroke,C=A.band,H=c.dir*(0==c.ori?1:-1),F=1==H?a:o;F>=a&&o>=F;F+=H){var R=f[F];if(null==R){if(!W)continue;var L=e(f,1==H?a:o,F,-H),I=e(f,F,1==H?o:a,H),N=f[L];R=N+(F-L)/(I-L)*(f[I]-N)}var O=h(2==c.distr?F:u[F],c,g,m),V=d(R,v,b,p),j=k(O-P),G=k(w(V,D)),U=k(x(V,D)),B=G-U;null!=f[F]&&y(Y,j,U,E,B),W&&(G=U,y(C,j,U=_,E,B=G-U))}return null!=s.fill&&(A.fill=new Path2D(Y)),A}))},br}();
