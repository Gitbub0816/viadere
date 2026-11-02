import Foundation
import Vapor
import ViadereCore

/// The console design system shared by the business console (`/dashboard`) and the operator console (`/operator`). See
/// `docs/ops/CONSOLE-UI.md` for how to build a page with it.
///
/// Rules every component follows:
/// * **Escaping.** A parameter typed `String` and named for text (`title`, `label`, `help`, `message`, …) is HTML-escaped here. A parameter
///   named `html` (or ending in `HTML`) is trusted markup the caller built from other components or escaped itself.
/// * **No script, no inline style.** Components are plain HTML styled by the one stylesheet below, which the CSP pins by its SHA-256
///   (`DashboardUI.csp`). Interactive patterns use native elements (`details`, forms, links), so every action works without script; the
///   only script on any console page is the passkey ceremony.
/// * **Accessible by construction.** Labels for every control, captions and `scope` on tables, text on every status (never colour alone),
///   visible focus, targets of at least 24 CSS pixels, tokens that meet WCAG AA in light and dark.
enum ConsoleUI {
    static func esc(_ text: String) -> String { WebRoutes.escape(text) }

    // MARK: - Stylesheet

    /// Tokens first (the contrast test reads the light block before the dark media query, and the first 400 characters of the dark block).
    static let css = """
    :root{color-scheme:light dark;--bg:#F5F2EC;--sf:#FCFBF8;--sr:#FFFFFF;--sk:#EEEAE2;--fg:#1F1E1C;--mu:#5E5951;--ac:#6F5A3C;--dg:#A13F2C;--ok:#3B5D45;--wa:#835414;--bd:#8A847A;--pf:#1F1E1C;--op:#F5F2EC;\
    --hl:rgba(31,30,28,.11);--hl2:rgba(31,30,28,.18);--acs:rgba(194,174,142,.20);--oks:rgba(59,93,69,.11);--dgs:rgba(161,63,44,.09);--was:rgba(160,110,20,.12);--mus:rgba(31,30,28,.06);\
    --sh:0 1px 2px rgba(31,30,28,.05),0 1px 1px rgba(31,30,28,.03);--sh2:0 10px 30px rgba(31,30,28,.12);\
    --fs-xs:.75rem;--fs-sm:.8125rem;--fs-md:.9375rem;--fs-lg:1.0625rem;--fs-xl:1.25rem;--fs-2xl:1.75rem;--fs-3xl:2.1rem;\
    --s1:.25rem;--s2:.5rem;--s3:.75rem;--s4:1rem;--s5:1.5rem;--s6:2rem;--s7:3rem;--r1:8px;--r2:12px;--r3:16px;--side:252px}
    @media(prefers-color-scheme:dark){:root{--bg:#121211;--sf:#1C1B1A;--sr:#262523;--sk:#232220;--fg:#F3F0EA;--mu:#A8A39A;--ac:#CDB993;--dg:#EC8B73;--ok:#94C39F;--wa:#E2B566;--bd:#77726A;--pf:#F3F0EA;--op:#1F1E1C;\
    --hl:rgba(243,240,234,.12);--hl2:rgba(243,240,234,.2);--acs:rgba(205,185,147,.15);--oks:rgba(148,195,159,.13);--dgs:rgba(236,139,115,.13);--was:rgba(226,181,102,.13);--mus:rgba(243,240,234,.07);\
    --sh:0 1px 2px rgba(0,0,0,.3);--sh2:0 12px 32px rgba(0,0,0,.45)}}
    *,*::before,*::after{box-sizing:border-box}html{-webkit-text-size-adjust:100%;text-size-adjust:100%}
    body{margin:0;background:var(--bg);color:var(--fg);font:var(--fs-md)/1.55 -apple-system,"SF Pro Text","Segoe UI",system-ui,"Helvetica Neue",sans-serif;-webkit-font-smoothing:antialiased}
    a{color:var(--ac);text-decoration:underline;text-underline-offset:2px;text-decoration-thickness:1px}a:hover{text-decoration-thickness:2px}
    h1,h2,h3,h4{color:var(--fg);margin:0}
    h1{font-size:var(--fs-2xl);font-weight:300;letter-spacing:-.015em;line-height:1.2}
    h2{font-size:var(--fs-lg);font-weight:600;letter-spacing:-.003em;line-height:1.35;margin:0 0 var(--s3)}
    h3{font-size:var(--fs-xs);font-weight:650;letter-spacing:.07em;text-transform:uppercase;color:var(--mu);margin:var(--s4) 0 var(--s2)}
    p{margin:var(--s2) 0 var(--s3)}ul,ol{margin:var(--s2) 0 var(--s3);padding-left:1.25rem}li+li{margin-top:.2rem}
    .mu{color:var(--mu)}.sm{font-size:var(--fs-sm)}.err{color:var(--dg)}.mono,code,pre,kbd{font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace;font-size:.86em}
    code{background:var(--mus);padding:.05rem .3rem;border-radius:5px;overflow-wrap:anywhere}
    pre{background:var(--sr);border:1px solid var(--hl);border-radius:var(--r2);padding:var(--s3) var(--s4);overflow:auto;white-space:pre-wrap;word-break:break-all;margin:var(--s2) 0 var(--s3)}pre code{background:none;padding:0}
    hr{border:0;border-top:1px solid var(--hl);margin:var(--s5) 0}
    .vh{position:absolute!important;width:1px;height:1px;margin:-1px;padding:0;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
    :focus-visible{outline:2px solid var(--ac);outline-offset:2px}
    .btn:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible,a:focus-visible,summary:focus-visible{outline:2px solid var(--ac);outline-offset:2px}
    main:focus{outline:none}[id]{scroll-margin-top:4.5rem}
    .ico{width:18px;height:18px;flex:none;fill:none;stroke:currentColor;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}
    .skip{position:absolute;left:var(--s2);top:-4rem;z-index:50;background:var(--pf);color:var(--op);padding:.6rem 1rem;border-radius:999px;font-weight:600;text-decoration:none}.skip:focus{top:var(--s2)}
    .shell{display:grid;grid-template-columns:var(--side) minmax(0,1fr);min-height:100vh}
    .side{position:sticky;top:0;align-self:start;height:100vh;overflow-y:auto;background:var(--sf);border-right:1px solid var(--hl);display:flex;flex-direction:column;gap:var(--s4);padding:var(--s5) var(--s3) var(--s4)}
    .brand{display:flex;align-items:center;gap:.6rem;color:var(--fg);font-size:1.22rem;letter-spacing:-.008em;text-decoration:none;padding:0 var(--s2)}.brand svg{width:34px;height:auto;flex:none}.brand b{font-weight:600}.brand span{font-weight:300}
    .brand .realm{margin-left:auto}
    .org{padding:var(--s3);border:1px solid var(--hl);border-radius:var(--r2);background:var(--bg);display:grid;gap:.15rem}.org .k{font-size:var(--fs-xs);color:var(--mu);letter-spacing:.04em;text-transform:uppercase}.org strong{font-weight:600;overflow-wrap:anywhere}.org .pill{justify-self:start;margin-top:.2rem}
    .side>nav{display:flex;flex-direction:column;gap:1px}
    .nav-g{font-size:var(--fs-xs);font-weight:650;letter-spacing:.08em;text-transform:uppercase;color:var(--mu);margin:var(--s4) var(--s3) var(--s1)}
    .side>nav a{display:flex;align-items:center;gap:.65rem;min-height:2.25rem;padding:.4rem .7rem;border-radius:10px;color:var(--fg);font-size:.9rem;text-decoration:none}
    .side>nav a .ico{color:var(--mu)}.side>nav a:hover{background:var(--acs)}.side>nav a[aria-current=page]{background:var(--acs);color:var(--ac);font-weight:600;box-shadow:inset 3px 0 0 var(--ac)}.side>nav a[aria-current=page] .ico{color:var(--ac)}
    .side-foot{margin-top:auto;padding:var(--s3) var(--s2) 0;border-top:1px solid var(--hl);font-size:var(--fs-sm);display:grid;gap:.35rem}.side-foot a{color:var(--mu)}
    .frame{min-width:0;display:flex;flex-direction:column}
    .top{position:sticky;top:0;z-index:20;display:flex;align-items:center;justify-content:space-between;gap:var(--s4);min-height:3.25rem;padding:.45rem clamp(1rem,3vw,2.25rem);background:var(--bg);background:color-mix(in srgb,var(--bg) 90%,transparent);-webkit-backdrop-filter:saturate(1.4) blur(10px);backdrop-filter:saturate(1.4) blur(10px);border-bottom:1px solid var(--hl)}
    .crumbs ol{list-style:none;margin:0;padding:0;display:flex;flex-wrap:wrap;align-items:center;font-size:var(--fs-sm);color:var(--mu)}.crumbs li{display:flex;align-items:center;margin:0}
    .crumbs li+li::before{content:"";display:inline-block;width:.38rem;height:.38rem;border-right:1.5px solid var(--bd);border-top:1.5px solid var(--bd);transform:rotate(45deg);margin:0 .6rem 0 .3rem}
    .crumbs a{color:var(--mu);text-decoration:none}.crumbs a:hover{color:var(--fg);text-decoration:underline}.crumbs [aria-current=page]{color:var(--fg);font-weight:600}
    .who{display:flex;align-items:center;gap:var(--s3);font-size:var(--fs-sm);color:var(--mu);white-space:nowrap}.who strong{color:var(--fg);font-weight:600}.who form{margin:0}
    main{padding:var(--s6) clamp(1rem,3vw,2.25rem) var(--s7);width:100%;max-width:1280px}
    .ph{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:flex-end;gap:var(--s4);margin-bottom:var(--s5)}.ph .sub{color:var(--mu);margin:.35rem 0 0;max-width:46rem}.ph .acts{display:flex;flex-wrap:wrap;gap:var(--s2);align-items:center}
    .head{display:flex;justify-content:space-between;align-items:flex-end;gap:1rem;flex-wrap:wrap;margin-bottom:1.5rem}
    .tabs{display:flex;gap:var(--s5);margin:calc(-1 * var(--s2)) 0 var(--s5);padding:0;border-bottom:1px solid var(--hl);overflow-x:auto;scrollbar-width:thin}
    .tabs a{display:inline-flex;align-items:center;min-height:2.5rem;padding:.35rem 0;margin-bottom:-1px;border-bottom:2px solid transparent;color:var(--mu);font-size:.9rem;white-space:nowrap;text-decoration:none}.tabs a:hover{color:var(--fg)}
    .tabs a[aria-current=page]{color:var(--fg);font-weight:600;border-bottom-color:var(--ac)}
    .card{background:var(--sf);border:1px solid var(--hl);border-radius:var(--r3);padding:var(--s5);margin-bottom:var(--s4);box-shadow:var(--sh);min-width:0}
    .card-h{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:flex-start;gap:var(--s3);margin-bottom:var(--s4)}.card-h h2{margin:0}.card-h .d{color:var(--mu);font-size:var(--fs-sm);margin:.3rem 0 0;max-width:52rem}.card-h .a{display:flex;flex-wrap:wrap;gap:var(--s2)}
    .card>:last-child{margin-bottom:0}.card.t-danger{border-color:var(--dg)}.card.t-danger h2{color:var(--dg)}.card.t-warning{border-color:var(--wa)}.card.flush{padding:0;overflow:hidden}.card.flush>.card-h{padding:var(--s5) var(--s5) 0}
    .sec{margin:var(--s6) 0 var(--s3)}.sec h2{margin:0}.sec p{color:var(--mu);font-size:var(--fs-sm);margin:.25rem 0 0}
    .cols{display:grid;gap:var(--s4);grid-template-columns:repeat(auto-fit,minmax(min(100%,260px),1fr))}.cols>*{min-width:0}
    .split{display:grid;gap:var(--s4);grid-template-columns:minmax(0,1fr) minmax(0,360px);align-items:start}.split.wa{grid-template-columns:minmax(0,1fr) minmax(0,430px)}
    .loop-editor>fieldset{background:var(--bg)}.loop-editor fieldset fieldset{background:var(--sf)}.loop-editor fieldset fieldset fieldset{background:var(--bg)}.loop-editor legend{font-size:.95rem}
    .row{display:flex;gap:var(--s2);flex-wrap:wrap;align-items:center}.row.end{justify-content:flex-end}.row>form{margin:0}
    .kpis,.grid{display:grid;gap:var(--s3);grid-template-columns:repeat(auto-fit,minmax(min(100%,190px),1fr));margin-bottom:var(--s4)}
    .stat{display:block;background:var(--sf);border:1px solid var(--hl);border-radius:var(--r3);padding:var(--s4) var(--s4) .9rem;color:var(--fg);text-decoration:none;box-shadow:var(--sh);min-width:0}
    .stat .n{font-size:var(--fs-3xl);font-weight:300;letter-spacing:-.02em;line-height:1.1;font-variant-numeric:tabular-nums;overflow-wrap:anywhere}.stat .l{font-size:var(--fs-sm);color:var(--mu);margin-top:.3rem}.stat .h{font-size:var(--fs-xs);color:var(--mu);margin-top:.35rem}
    a.stat:hover{border-color:var(--ac)}.stat.t-danger{border-color:var(--dg)}.stat.t-danger .n{color:var(--dg)}.stat.t-warning{border-color:var(--wa)}.stat.t-warning .n{color:var(--wa)}.stat.t-success .n{color:var(--ok)}
    .card .stat{box-shadow:none;background:var(--bg)}
    .tw{overflow-x:auto;margin:0 0 var(--s3);-webkit-overflow-scrolling:touch}
    table{width:100%;border-collapse:separate;border-spacing:0;font-size:.9rem}
    th{font-size:var(--fs-xs);font-weight:650;letter-spacing:.06em;text-transform:uppercase;color:var(--mu);text-align:left;padding:.6rem .7rem;border-bottom:1px solid var(--hl2);white-space:nowrap;background:var(--sf)}
    td{padding:.7rem .7rem;border-bottom:1px solid var(--hl);vertical-align:top}tbody tr:last-child td{border-bottom:0}tbody tr:hover td{background:var(--mus)}
    th[scope=row]{text-transform:none;letter-spacing:0;font-size:.9rem;color:var(--fg);white-space:normal;background:none;border-bottom:1px solid var(--hl)}
    .num{text-align:right;font-variant-numeric:tabular-nums}.act{text-align:right;white-space:nowrap}.act .row{justify-content:flex-end}
    td>form,td .row>form{margin:0}td>form+form{margin-top:var(--s2)}
    th a.sort{display:inline-flex;align-items:center;gap:.25rem;color:inherit;text-decoration:none}th a.sort:hover{color:var(--fg)}th a.sort .ico{width:14px;height:14px;opacity:.55}th[aria-sort] a.sort{color:var(--fg)}th[aria-sort] a.sort .ico{opacity:1}
    table caption{caption-side:top;text-align:left;font-weight:600;padding:.25rem .7rem .5rem}
    .pager{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:var(--s2);padding-top:var(--s3);font-size:var(--fs-sm);color:var(--mu)}
    .empty{display:grid;justify-items:center;gap:.2rem;text-align:center;padding:var(--s6) var(--s4);border:1px dashed var(--hl2);border-radius:var(--r2);background:var(--bg);color:var(--mu);margin:0 0 var(--s3)}
    .empty .ico{width:28px;height:28px;color:var(--bd);margin-bottom:.25rem}.empty .t{color:var(--fg);font-weight:600;margin:0}.empty p{margin:0;max-width:34rem}.empty .row{margin-top:var(--s3);justify-content:center}
    .btn{display:inline-flex;align-items:center;justify-content:center;gap:.45rem;min-height:2.25rem;padding:.45rem 1.05rem;border:1px solid transparent;border-radius:999px;font:inherit;font-size:.9rem;font-weight:600;line-height:1.2;cursor:pointer;background:var(--pf);color:var(--op);text-decoration:none;white-space:nowrap;transition:background-color .15s,border-color .15s,opacity .15s}
    .btn:hover{opacity:.9;text-decoration:none}.btn .ico{width:16px;height:16px}
    .btn.s{background:var(--sr);color:var(--fg);border-color:var(--bd)}.btn.s:hover{background:var(--acs);opacity:1}
    .btn.g{background:transparent;color:var(--fg);border-color:transparent}.btn.g:hover{background:var(--acs);opacity:1}
    .btn.d{background:var(--sr);color:var(--dg);border-color:var(--dg)}.btn.d:hover{background:var(--dgs);opacity:1}
    .btn.dd{background:var(--dg);color:var(--sr);border-color:var(--dg)}
    .btn.sm{min-height:1.85rem;padding:.25rem .8rem;font-size:var(--fs-sm)}
    .btn[disabled],.btn[aria-disabled=true]{opacity:.45;cursor:not-allowed}
    .pk-note{display:flex;align-items:center;gap:.4rem;font-size:var(--fs-sm);color:var(--mu);margin:var(--s2) 0}.pk-note .ico{width:15px;height:15px;color:var(--ac)}
    form{margin:0}form+form{margin-top:var(--s3)}
    label{display:block;font-size:.85rem;font-weight:600;margin:var(--s3) 0 .3rem}
    .field{margin:0 0 var(--s4)}.field>label{margin:0 0 .35rem}.field .opt{font-weight:400;color:var(--mu)}
    input[type=text],input[type=email],input[type=url],input[type=number],input[type=search],input[type=tel],input[type=date],input[type=datetime-local],input[type=time],input[type=password],select,textarea{width:100%;min-height:2.4rem;padding:.5rem .75rem;border-radius:var(--r1);border:1px solid var(--bd);background:var(--sr);color:var(--fg);font:inherit;font-size:.92rem;transition:border-color .15s,box-shadow .15s}
    input[type=number]{max-width:14rem}textarea{min-height:6rem;resize:vertical;line-height:1.5}
    input:hover,select:hover,textarea:hover{border-color:var(--fg)}
    input:focus-visible,select:focus-visible,textarea:focus-visible{border-color:var(--ac);box-shadow:0 0 0 3px var(--acs)}
    input:disabled,select:disabled,textarea:disabled{opacity:.6;cursor:not-allowed;background:var(--sk)}
    input[type=color]{width:3.25rem;height:2.4rem;padding:.2rem;border:1px solid var(--bd);border-radius:var(--r1);background:var(--sr)}
    input[type=file]{font:inherit;font-size:var(--fs-sm);max-width:100%}
    [aria-invalid=true],input:user-invalid,select:user-invalid,textarea:user-invalid{border-color:var(--dg)}
    .help{font-size:var(--fs-sm);color:var(--mu);margin:.35rem 0 0}.ferr{display:flex;gap:.35rem;align-items:flex-start;font-size:var(--fs-sm);color:var(--dg);font-weight:600;margin:.35rem 0 0}.ferr .ico{width:15px;height:15px;margin-top:.15rem}
    .vmsg{display:none;font-size:var(--fs-sm);color:var(--dg);margin:.35rem 0 0}.field:has(:user-invalid) .vmsg{display:block}
    fieldset{border:1px solid var(--hl);border-radius:var(--r2);padding:var(--s3) var(--s4) var(--s2);margin:0 0 var(--s4);min-width:0}legend{font-weight:600;font-size:.9rem;padding:0 .35rem}fieldset>.help:first-of-type{margin-top:0}
    .ck{display:flex;align-items:flex-start;gap:.55rem;font-weight:400;font-size:.92rem;margin:.35rem 0;min-height:1.75rem;line-height:1.45}.ck input{width:1.15rem;height:1.15rem;margin:.12rem 0 0;flex:none;accent-color:var(--ac)}
    .choices{display:grid;gap:var(--s2);grid-template-columns:repeat(auto-fit,minmax(min(100%,220px),1fr));margin:var(--s2) 0}
    .choice{display:flex;gap:.6rem;align-items:flex-start;margin:0;padding:.7rem .85rem;border:1px solid var(--bd);border-radius:var(--r2);background:var(--sr);font-weight:400;cursor:pointer}.choice input{margin-top:.2rem;accent-color:var(--ac);width:1.1rem;height:1.1rem;flex:none}
    .choice:has(:checked){border-color:var(--ac);box-shadow:0 0 0 2px var(--acs)}.choice strong{display:block;font-weight:600}.choice .help{margin-top:.15rem}.choice.t-danger:has(:checked){border-color:var(--dg);box-shadow:0 0 0 2px var(--dgs)}
    .form-actions{display:flex;flex-wrap:wrap;gap:var(--s2);align-items:center;margin-top:var(--s4)}.form-actions.sep{padding-top:var(--s4);border-top:1px solid var(--hl)}.form-actions .pk-note{margin:0}
    .inline{display:flex;flex-wrap:wrap;gap:var(--s2);align-items:flex-end}.inline .field{margin:0;flex:1 1 12rem}.inline .field.n{flex:0 0 8rem}
    .pill,.badge{display:inline-flex;align-items:center;gap:.35rem;padding:.12rem .6rem;border-radius:999px;font-size:var(--fs-xs);font-weight:650;line-height:1.5;white-space:nowrap;vertical-align:middle;background:var(--acs);color:var(--ac)}
    .pill::before{content:"";width:.42rem;height:.42rem;border-radius:50%;background:currentColor;flex:none}
    .t-accent.pill{background:var(--acs);color:var(--ac)}.t-success.pill,.badge.ok{background:var(--oks);color:var(--ok)}.t-danger.pill,.badge.dg{background:var(--dgs);color:var(--dg)}.t-warning.pill,.badge.wa{background:var(--was);color:var(--wa)}.t-neutral.pill,.badge.mu{background:var(--mus);color:var(--mu)}
    .notice,.callout{display:flex;gap:.75rem;align-items:flex-start;border:1px solid var(--hl);border-left:3px solid var(--ac);background:var(--sf);border-radius:var(--r2);padding:.8rem 1rem;margin-bottom:var(--s4)}
    .callout>.ico{margin-top:.1rem;color:var(--ac)}.callout>div{min-width:0;flex:1}.callout p{margin:.15rem 0}.callout .t{font-weight:600;margin:0 0 .15rem}.callout ul{margin:.3rem 0 0}
    .notice.dg,.callout.t-danger{border-left-color:var(--dg);background:var(--dgs)}.callout.t-danger>.ico{color:var(--dg)}
    .notice.ok,.callout.t-success{border-left-color:var(--ok);background:var(--oks)}.callout.t-success>.ico{color:var(--ok)}
    .callout.t-warning{border-left-color:var(--wa);background:var(--was)}.callout.t-warning>.ico{color:var(--wa)}.callout.t-neutral{border-left-color:var(--bd)}.callout.t-neutral>.ico{color:var(--mu)}
    .toast{display:flex;gap:.7rem;align-items:center;background:var(--pf);color:var(--op);border-radius:var(--r2);padding:.75rem 1rem;margin-bottom:var(--s4);box-shadow:var(--sh2);animation:toast-in .28s ease-out}
    .toast p{margin:0}.toast .ico{color:var(--op)}.toast.t-danger{box-shadow:inset 4px 0 0 var(--dg),var(--sh2)}.toast.t-warning{box-shadow:inset 4px 0 0 var(--wa),var(--sh2)}
    @keyframes toast-in{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}
    .kv{display:grid;grid-template-columns:minmax(9rem,max-content) minmax(0,1fr);gap:.55rem 1.5rem;margin:0}.kv dt{color:var(--mu);font-size:var(--fs-sm)}.kv dd{margin:0;overflow-wrap:anywhere}
    .progress{display:flex;align-items:center;gap:var(--s3);font-size:var(--fs-sm);color:var(--mu);margin-bottom:var(--s4)}.progress strong{color:var(--fg)}
    progress{-webkit-appearance:none;appearance:none;flex:1;height:.5rem;border:0;border-radius:999px;background:var(--hl);overflow:hidden;color:var(--ok)}
    progress::-webkit-progress-bar{background:var(--hl);border-radius:999px}progress::-webkit-progress-value{background:var(--ok);border-radius:999px}progress::-moz-progress-bar{background:var(--ok);border-radius:999px}
    .checklist,.steps{list-style:none;margin:0;padding:0;display:grid;gap:var(--s2)}
    .checklist li,.steps li{display:flex;gap:.75rem;align-items:flex-start;padding:.75rem .9rem;border:1px solid var(--hl);border-radius:var(--r2);background:var(--bg);margin:0}
    .checklist .dot{flex:none;display:inline-grid;place-items:center;width:1.6rem;height:1.6rem;border-radius:50%;border:1.5px solid var(--bd);font-size:var(--fs-xs);font-weight:700;color:var(--mu)}
    .checklist li.done .dot{background:var(--ok);border-color:var(--ok);color:var(--sf)}.checklist li.done .dot .ico{width:14px;height:14px;stroke-width:2.4}.checklist li.now{border-color:var(--ac);box-shadow:0 0 0 2px var(--acs)}
    .checklist .ct{margin:0;font-weight:600}.checklist .cd{margin:.15rem 0 0;font-size:var(--fs-sm);color:var(--mu)}.steps .done{border-color:var(--ok)}
    .plain{list-style:none;padding:0}
    .timeline{list-style:none;margin:0;padding:0}.timeline li{position:relative;padding:0 0 var(--s4) 1.4rem;margin:0;border-left:1px solid var(--hl2);margin-left:.4rem}.timeline li:last-child{border-left-color:transparent;padding-bottom:0}
    .timeline li::before{content:"";position:absolute;left:-.38rem;top:.35rem;width:.7rem;height:.7rem;border-radius:50%;background:var(--sf);border:2px solid var(--ac)}.timeline .m{font-size:var(--fs-sm);color:var(--mu)}
    details.confirm{display:inline-block;vertical-align:top}details.confirm>summary{list-style:none}details.confirm>summary::-webkit-details-marker{display:none}
    .confirm-pop{margin-top:var(--s2);padding:var(--s3) var(--s4);border:1px solid var(--dg);border-radius:var(--r2);background:var(--sr);min-width:min(18rem,75vw);max-width:26rem;text-align:left;white-space:normal;box-shadow:var(--sh2)}.confirm-pop p{margin:0 0 var(--s2);font-size:var(--fs-sm)}
    details.more>summary{cursor:pointer;color:var(--ac);font-weight:600;font-size:var(--fs-sm);padding:.3rem 0}details.more[open]>summary{margin-bottom:var(--s2)}
    .diff{display:grid;gap:var(--s3);grid-template-columns:repeat(auto-fit,minmax(min(100%,320px),1fr))}.diff figure{margin:0;border:1px solid var(--hl);border-radius:var(--r2);overflow:hidden;background:var(--sr);min-width:0}
    .diff figcaption{display:flex;justify-content:space-between;gap:var(--s2);padding:.5rem .8rem;font-size:var(--fs-sm);font-weight:600;background:var(--sk);border-bottom:1px solid var(--hl)}
    .code{margin:0;padding:.4rem 0;list-style:none;overflow-x:auto;font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace;font-size:.8rem;line-height:1.55;counter-reset:ln}
    .code li{margin:0;padding:0 .8rem 0 3.2rem;white-space:pre;position:relative;counter-increment:ln}.code li::before{content:counter(ln);position:absolute;left:0;width:2.4rem;text-align:right;color:var(--mu);opacity:.7}
    .code li.del{background:var(--dgs);box-shadow:inset 3px 0 0 var(--dg)}.code li.add{background:var(--oks);box-shadow:inset 3px 0 0 var(--ok)}
    .device{display:inline-block;max-width:100%;padding:10px;border:1px solid var(--hl2);border-radius:30px;background:var(--sk)}.device iframe{display:block;border-radius:22px}
    iframe{max-width:100%;border:1px solid var(--hl);border-radius:var(--r2);background:#fff}
    .sw{display:inline-flex;align-items:center;gap:.45rem}.sw svg{width:18px;height:18px;flex:none;border-radius:4px;box-shadow:0 0 0 1px var(--hl2)}
    .secret{font-size:.95rem;padding:.9rem 1rem;border:1px dashed var(--ac);border-radius:var(--r2);background:var(--acs);word-break:break-all;-webkit-user-select:all;user-select:all}
    .qr{width:224px;height:224px;background:#fff;border-radius:var(--r2);padding:8px;display:block}.qr svg{width:100%;height:100%;display:block}
    .bars rect.b{fill:var(--ac)}.bars rect.t{fill:var(--hl2)}.bars text{fill:var(--mu);font:11px -apple-system,system-ui,sans-serif}
    .seg{display:inline-flex;padding:3px;border:1px solid var(--hl2);border-radius:999px;background:var(--sf);gap:2px}.seg a{padding:.3rem .8rem;border-radius:999px;font-size:var(--fs-sm);font-weight:600;color:var(--mu);text-decoration:none;min-height:1.85rem;display:inline-flex;align-items:center}
    .seg a:hover{color:var(--fg)}.seg a[aria-current=page]{background:var(--pf);color:var(--op)}
    .attn{display:grid;gap:var(--s2);margin:0;padding:0;list-style:none}.attn li{display:flex;gap:.7rem;align-items:center;justify-content:space-between;flex-wrap:wrap;padding:.7rem .9rem;border:1px solid var(--hl);border-radius:var(--r2);background:var(--bg);margin:0}
    .attn li>div{display:flex;gap:.7rem;align-items:center;min-width:0}.attn .ico{color:var(--ac)}.attn .t-danger .ico{color:var(--dg)}.attn .t-warning .ico{color:var(--wa)}
    .auth{max-width:31rem;margin:7vh auto;padding:0 1rem}.auth .brand{justify-content:center;margin-bottom:var(--s5);font-size:1.4rem}.auth .card{padding:var(--s6) var(--s6) var(--s5)}.auth h1{margin-bottom:var(--s2)}.auth .foot{text-align:center;font-size:var(--fs-sm);color:var(--mu);margin-top:var(--s4)}
    .auth .btn.wide,.btn.wide{width:100%}
    .op .side{background:var(--pf);color:var(--op);border-right-color:transparent}.op .side .brand{color:var(--op)}.op .side>nav a{color:var(--op)}.op .side>nav a .ico{color:var(--op);opacity:.7}
    .op .side>nav a:hover{background:rgba(127,127,127,.18)}.op .side>nav a[aria-current=page]{background:rgba(127,127,127,.22);color:var(--op);box-shadow:inset 3px 0 0 var(--op)}.op .side>nav a[aria-current=page] .ico{opacity:1}
    .op .side .nav-g{color:var(--op);opacity:.72}.op .side .org{background:transparent;border-color:rgba(127,127,127,.35)}.op .side .org .k{color:var(--op);opacity:.75}.op .side-foot{border-top-color:rgba(127,127,127,.35)}.op .side-foot a{color:var(--op)}
    .op .side .pill{background:var(--op);color:var(--pf)}
    @media(max-width:1100px){.split{grid-template-columns:minmax(0,1fr)}}
    @media(max-width:820px){.shell{grid-template-columns:minmax(0,1fr)}.side{position:static;height:auto;overflow:visible;flex-direction:row;flex-wrap:wrap;align-items:center;gap:var(--s2);padding:var(--s3) var(--s4);border-right:0;border-bottom:1px solid var(--hl)}
    .side>nav{order:3;width:100%;flex-direction:row;overflow-x:auto;gap:var(--s1);padding-bottom:var(--s1);scrollbar-width:thin}.side>nav a{white-space:nowrap;min-height:2.25rem}.nav-g,.org,.side-foot{display:none}.brand .realm{margin-left:var(--s2)}
    .top{position:static}main{padding-top:var(--s5)}.who .nm{display:none}}
    @media(max-width:560px){h1{font-size:1.45rem}main{padding:var(--s4) var(--s4) var(--s6)}.card{padding:var(--s4);border-radius:var(--r2)}.kv{grid-template-columns:minmax(0,1fr)}.kv dd{margin-bottom:var(--s2)}
    .ph{align-items:flex-start}.form-actions .btn{flex:1 1 auto}.top{flex-wrap:wrap}.stat .n{font-size:var(--fs-2xl)}.auth .card{padding:var(--s5) var(--s4)}}
    @media(prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}}
    @media(forced-colors:active){.btn,.pill,.badge,.stat,.card,.callout,.notice,.toast{border:1px solid CanvasText}.side>nav a[aria-current=page],.tabs a[aria-current=page]{outline:2px solid Highlight}}
    @media print{.side,.top,.skip,.form-actions,form{display:none!important}.shell{display:block}.card{box-shadow:none;break-inside:avoid}}
    """

    // MARK: - Tones and icons

    /// Semantic tones. Never the only signal: every pill, callout and stat that carries a tone also carries text.
    enum Tone: String, Sendable {
        case neutral, accent, success, warning, danger
        var cls: String { "t-" + rawValue }
    }

    /// Maps the legacy badge kinds (`ok`, `dg`, `mu`, `wa`, empty) used across the console.
    static func tone(legacy kind: String) -> Tone {
        switch kind {
        case "ok": .success
        case "dg": .danger
        case "mu": .neutral
        case "wa": .warning
        default: .accent
        }
    }

    /// Line icons (24 px grid, stroke only, `aria-hidden`). Brand rule: no shield imagery.
    enum Icon: String, CaseIterable, Sendable {
        case home, chat, inbox, loop, verify, approve, code, building, lock, document, card, help, queue, store, alert, sliders, palette, toggle,
             users, megaphone, archive, key, check, info, error, plus, sortUp, sortDown, sort, external, signout, clock, chart

        var paths: String {
            switch self {
            case .home: "<path d=\"M3 11l9-7 9 7\"/><path d=\"M5 10v10h14V10\"/><path d=\"M10 20v-5h4v5\"/>"
            case .chat: "<path d=\"M4 5h16v11H9l-5 4z\"/><path d=\"M8 9.5h8M8 12.5h5\"/>"
            case .inbox: "<path d=\"M3 13l3-8h12l3 8v6H3z\"/><path d=\"M3 13h5l1.5 2.5h5L16 13h5\"/>"
            case .loop: "<path d=\"M17 2l3 3-3 3\"/><path d=\"M4 11V9a4 4 0 0 1 4-4h12\"/><path d=\"M7 22l-3-3 3-3\"/><path d=\"M20 13v2a4 4 0 0 1-4 4H4\"/>"
            case .verify: "<rect x=\"3\" y=\"5\" width=\"18\" height=\"14\" rx=\"2\"/><circle cx=\"9\" cy=\"11\" r=\"2\"/><path d=\"M6 16c.8-1.4 1.9-2 3-2s2.2.6 3 2\"/><path d=\"M15 10h3M15 13.5h3\"/>"
            case .approve: "<circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M8 12.5l2.7 2.7L16.2 9.5\"/>"
            case .code: "<path d=\"M8 8l-4 4 4 4M16 8l4 4-4 4M13.5 5l-3 14\"/>"
            case .building: "<path d=\"M4 21V5.5L12 3v18M12 9h8v12M3 21h18\"/><path d=\"M8 8h.01M8 12h.01M8 16h.01M16 13h.01M16 17h.01\"/>"
            case .lock: "<rect x=\"5\" y=\"11\" width=\"14\" height=\"10\" rx=\"2\"/><path d=\"M8 11V7.5a4 4 0 0 1 8 0V11\"/><path d=\"M12 15v2\"/>"
            case .document: "<path d=\"M6 3h9l3 3v15H6z\"/><path d=\"M15 3v3h3M9 11h6M9 14.5h6M9 18h4\"/>"
            case .card: "<rect x=\"3\" y=\"6\" width=\"18\" height=\"13\" rx=\"2\"/><path d=\"M3 10h18M7 15h3\"/>"
            case .help: "<circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M9.6 9.4a2.5 2.5 0 1 1 3.4 2.4c-.6.3-1 .8-1 1.5v.4\"/><path d=\"M12 17h.01\"/>"
            case .queue: "<path d=\"M4 6h16M4 12h16M4 18h10\"/><path d=\"M18 16l2 2-2 2\"/>"
            case .store: "<path d=\"M4 9l1.5-5h13L20 9\"/><path d=\"M4 9a2.7 2.7 0 0 0 5.3 0 2.7 2.7 0 0 0 5.4 0 2.7 2.7 0 0 0 5.3 0\"/><path d=\"M5 11.5V20h14v-8.5\"/>"
            case .alert: "<path d=\"M12 4l9 16H3z\"/><path d=\"M12 10v4M12 17h.01\"/>"
            case .sliders: "<path d=\"M4 7h10M18 7h2M4 17h4M12 17h8\"/><circle cx=\"16\" cy=\"7\" r=\"2\"/><circle cx=\"10\" cy=\"17\" r=\"2\"/>"
            case .palette: "<path d=\"M12 3a9 9 0 1 0 0 18c1 0 1.5-.7 1.5-1.5 0-1.2-1-1.5-1-2.5s.8-1.5 2-1.5H17a4 4 0 0 0 4-4C21 6.8 17 3 12 3z\"/><path d=\"M7.5 11h.01M10 7.5h.01M14.5 7.5h.01\"/>"
            case .toggle: "<rect x=\"2\" y=\"7\" width=\"20\" height=\"10\" rx=\"5\"/><circle cx=\"16\" cy=\"12\" r=\"2.5\"/>"
            case .users: "<circle cx=\"9\" cy=\"8\" r=\"3.5\"/><path d=\"M2.5 20c.8-3.3 3.3-5 6.5-5s5.7 1.7 6.5 5\"/><path d=\"M16 4.6a3.5 3.5 0 0 1 0 6.8M18 15.2c1.9.6 3.1 2.2 3.5 4.8\"/>"
            case .megaphone: "<path d=\"M3 10v4h4l8 5V5L7 10z\"/><path d=\"M18.5 9a4 4 0 0 1 0 6\"/>"
            case .archive: "<ellipse cx=\"12\" cy=\"5.5\" rx=\"8\" ry=\"2.5\"/><path d=\"M4 5.5v13c0 1.4 3.6 2.5 8 2.5s8-1.1 8-2.5v-13M4 12c0 1.4 3.6 2.5 8 2.5s8-1.1 8-2.5\"/>"
            case .key: "<circle cx=\"8\" cy=\"15\" r=\"4\"/><path d=\"M10.8 12.2L20 3M16.5 6.5l2 2M14.5 8.5l2 2\"/>"
            case .check: "<path d=\"M5 12.5l4.5 4.5L19 7.5\"/>"
            case .info: "<circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M12 11v5.5M12 7.8h.01\"/>"
            case .error: "<circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M12 7.5v5.5M12 16.5h.01\"/>"
            case .plus: "<path d=\"M12 5v14M5 12h14\"/>"
            case .sortUp: "<path d=\"M12 19V5M6.5 10.5L12 5l5.5 5.5\"/>"
            case .sortDown: "<path d=\"M12 5v14M6.5 13.5L12 19l5.5-5.5\"/>"
            case .sort: "<path d=\"M8 9.5l4-4 4 4M8 14.5l4 4 4-4\"/>"
            case .external: "<path d=\"M14 4h6v6M20 4l-9 9M18 14v6H4V6h6\"/>"
            case .signout: "<path d=\"M14 4h5v16h-5M10 8l-4 4 4 4M6 12h10\"/>"
            case .clock: "<circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M12 7v5l3 2\"/>"
            case .chart: "<path d=\"M4 20V4M4 20h16\"/><path d=\"M8 16v-4M12 16V8M16 16v-6\"/>"
            }
        }
    }

    static func icon(_ icon: Icon) -> String {
        "<svg class=\"ico\" viewBox=\"0 0 24 24\" aria-hidden=\"true\" focusable=\"false\">\(icon.paths)</svg>"
    }

    // MARK: - Status pills

    /// A status pill: a dot and the status in words.
    static func pill(_ text: String, _ tone: Tone = .accent) -> String {
        "<span class=\"pill \(tone.cls)\">\(esc(text))</span>"
    }

    // MARK: - Buttons and links

    enum ButtonStyle: Sendable {
        case primary, secondary, ghost, danger, dangerSolid
        var cls: String {
            switch self {
            case .primary: "btn"
            case .secondary: "btn s"
            case .ghost: "btn g"
            case .danger: "btn d"
            case .dangerSolid: "btn dd"
            }
        }
    }

    /// A form button. `passkey: true` marks an action that asks for the passkey (a key glyph; pair it with `passkeyNote`).
    static func button(_ label: String, _ style: ButtonStyle = .primary, small: Bool = false, name: String? = nil, value: String? = nil,
                       ariaLabel: String? = nil, passkey: Bool = false, icon: Icon? = nil, disabled: Bool = false, type: String = "submit", wide: Bool = false) -> String {
        var attributes = "class=\"\(style.cls)\(small ? " sm" : "")\(wide ? " wide" : "")\" type=\"\(esc(type))\""
        if let name { attributes += " name=\"\(esc(name))\"" }
        if let value { attributes += " value=\"\(esc(value))\"" }
        if let ariaLabel { attributes += " aria-label=\"\(esc(ariaLabel))\"" }
        if disabled { attributes += " disabled aria-disabled=\"true\"" }
        let glyph = passkey ? self.icon(.key) : (icon.map { self.icon($0) } ?? "")
        return "<button \(attributes)>\(glyph)\(esc(label))</button>"
    }

    /// A link styled as a button (navigation, never a state change).
    static func linkButton(_ label: String, href: String, _ style: ButtonStyle = .secondary, small: Bool = false, ariaLabel: String? = nil,
                           icon: Icon? = nil, current: Bool = false) -> String {
        "<a class=\"\(style.cls)\(small ? " sm" : "")\" href=\"\(esc(href))\"\(ariaLabel.map { " aria-label=\"\(esc($0))\"" } ?? "")\(current ? " aria-current=\"page\"" : "")>\(icon.map { self.icon($0) } ?? "")\(esc(label))</a>"
    }

    /// "Asks for your passkey" next to a sensitive action (the server enforces it; this tells the person before they click).
    static func passkeyNote(_ text: String = "You'll confirm with your passkey.") -> String {
        "<p class=\"pk-note\">\(icon(.key))<span>\(esc(text))</span></p>"
    }

    /// A segmented control of links (period pickers, filters). Exactly one item is current.
    static func segmented(_ items: [(title: String, href: String, current: Bool)], label: String) -> String {
        "<nav class=\"seg\" aria-label=\"\(esc(label))\">" + items.map {
            "<a href=\"\(esc($0.href))\"\($0.current ? " aria-current=\"page\"" : "")>\(esc($0.title))</a>"
        }.joined() + "</nav>"
    }

    // MARK: - Forms

    /// A POST form carrying the CSRF field (`DashboardUI.csrf(p)`, already markup).
    static func form(_ action: String, csrf: String, multipart: Bool = false, cls: String? = nil, ariaLabel: String? = nil, _ html: String) -> String {
        "<form method=\"post\" action=\"\(esc(action))\"\(multipart ? " enctype=\"multipart/form-data\"" : "")\(cls.map { " class=\"\(esc($0))\"" } ?? "")\(ariaLabel.map { " aria-label=\"\(esc($0))\"" } ?? "")>\(csrf)\(html)</form>"
    }

    static func hidden(_ name: String, _ value: String) -> String { "<input type=\"hidden\" name=\"\(esc(name))\" value=\"\(esc(value))\">" }

    /// The field id used when none is given: the name with every character outside `[A-Za-z0-9_-]` replaced.
    static func fieldId(_ name: String) -> String {
        "f-" + String(name.map { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") ? $0 : "-" })
    }

    /// What the browser's own validation will refuse, said in words (shown only once the field is invalid, via `:user-invalid`; no script).
    static func validationHint(type: String, required: Bool, attrs: [String: String]) -> String? {
        if type == "email" { return "Enter an email address, like name@example.com." }
        if type == "url" { return "Enter a full address that starts with https://." }
        if type == "number", let min = attrs["min"], let max = attrs["max"] { return "Enter a number from \(min) to \(max)." }
        if let min = attrs["minlength"] { return "Use at least \(min) characters." }
        if attrs["pattern"] != nil { return "Check the format." }
        return required ? "This field is required." : nil
    }

    private static func describedBy(_ id: String, help: Bool, error: Bool) -> String {
        let ids = (help ? ["\(id)-h"] : []) + (error ? ["\(id)-e"] : [])
        return ids.isEmpty ? "" : " aria-describedby=\"\(ids.joined(separator: " "))\""
    }

    private static func attributeString(_ attrs: [String: String]) -> String {
        attrs.keys.sorted().map { key in attrs[key] == "" ? " \(esc(key))" : " \(esc(key))=\"\(esc(attrs[key]!))\"" }.joined()
    }

    private static func fieldShell(id: String, label: String, optional: Bool, control: String, help: String?, helpHTML: String?, error: String?, hint: String?, cls: String?) -> String {
        var html = "<div class=\"field\(cls.map { " " + $0 } ?? "")\"><label for=\"\(esc(id))\">\(esc(label))\(optional ? "<span class=\"opt\"> (optional)</span>" : "")</label>\(control)"
        if let helpHTML { html += "<p class=\"help\" id=\"\(esc(id))-h\">\(helpHTML)</p>" } else if let help { html += "<p class=\"help\" id=\"\(esc(id))-h\">\(esc(help))</p>" }
        if let error { html += "<p class=\"ferr\" id=\"\(esc(id))-e\">\(icon(.error))<span>\(esc(error))</span></p>" }
        if let hint { html += "<p class=\"vmsg\">\(esc(hint))</p>" }
        return html + "</div>"
    }

    /// A labelled input with optional help text, a server error (`aria-invalid`, described by the error) and a script-free inline validation
    /// hint. `attrs` carries the HTML constraints (`maxlength`, `min`, `pattern`, `autocomplete`, `inputmode`, …); an empty value renders a
    /// bare attribute.
    static func input(_ name: String, label: String, id: String? = nil, type: String = "text", value: String? = nil, placeholder: String? = nil,
                      help: String? = nil, helpHTML: String? = nil, error: String? = nil, required: Bool = false, optional: Bool = false,
                      disabled: Bool = false, attrs: [String: String] = [:], cls: String? = nil) -> String {
        let id = id ?? fieldId(name)
        var control = "<input id=\"\(esc(id))\" name=\"\(esc(name))\" type=\"\(esc(type))\""
        if let value { control += " value=\"\(esc(value))\"" }
        if let placeholder { control += " placeholder=\"\(esc(placeholder))\"" }
        control += attributeString(attrs)
        if required { control += " required" }
        if disabled { control += " disabled" }
        if error != nil { control += " aria-invalid=\"true\"" }
        control += describedBy(id, help: help != nil || helpHTML != nil, error: error != nil) + ">"
        return fieldShell(id: id, label: label, optional: optional, control: control, help: help, helpHTML: helpHTML, error: error,
                          hint: disabled ? nil : validationHint(type: type, required: required, attrs: attrs), cls: cls)
    }

    static func textarea(_ name: String, label: String, id: String? = nil, value: String? = nil, placeholder: String? = nil, help: String? = nil,
                         helpHTML: String? = nil, error: String? = nil, required: Bool = false, optional: Bool = false, disabled: Bool = false,
                         attrs: [String: String] = [:], cls: String? = nil) -> String {
        let id = id ?? fieldId(name)
        var control = "<textarea id=\"\(esc(id))\" name=\"\(esc(name))\""
        if let placeholder { control += " placeholder=\"\(esc(placeholder))\"" }
        control += attributeString(attrs)
        if required { control += " required" }
        if disabled { control += " disabled" }
        if error != nil { control += " aria-invalid=\"true\"" }
        control += describedBy(id, help: help != nil || helpHTML != nil, error: error != nil) + ">\(esc(value ?? ""))</textarea>"
        return fieldShell(id: id, label: label, optional: optional, control: control, help: help, helpHTML: helpHTML, error: error,
                          hint: disabled ? nil : validationHint(type: "textarea", required: required, attrs: attrs), cls: cls)
    }

    struct Option: Sendable {
        var value: String
        var label: String
        var selected = false
        var disabled = false
        init(_ value: String, _ label: String, selected: Bool = false, disabled: Bool = false) {
            self.value = value; self.label = label; self.selected = selected; self.disabled = disabled
        }
    }

    static func options(_ options: [Option]) -> String {
        options.map { "<option value=\"\(esc($0.value))\"\($0.selected ? " selected" : "")\($0.disabled ? " disabled" : "")>\(esc($0.label))</option>" }.joined()
    }

    static func select(_ name: String, label: String, id: String? = nil, options: [Option], help: String? = nil, helpHTML: String? = nil,
                       error: String? = nil, required: Bool = false, optional: Bool = false, disabled: Bool = false, attrs: [String: String] = [:], cls: String? = nil) -> String {
        selectHTML(name, label: label, id: id, optionsHTML: self.options(options), help: help, helpHTML: helpHTML, error: error, required: required,
                   optional: optional, disabled: disabled, attrs: attrs, cls: cls)
    }

    /// A select whose options are already markup (option groups).
    static func selectHTML(_ name: String, label: String, id: String? = nil, optionsHTML: String, help: String? = nil, helpHTML: String? = nil,
                           error: String? = nil, required: Bool = false, optional: Bool = false, disabled: Bool = false, attrs: [String: String] = [:], cls: String? = nil) -> String {
        let id = id ?? fieldId(name)
        var control = "<select id=\"\(esc(id))\" name=\"\(esc(name))\"" + attributeString(attrs)
        if required { control += " required" }
        if disabled { control += " disabled" }
        if error != nil { control += " aria-invalid=\"true\"" }
        control += describedBy(id, help: help != nil || helpHTML != nil, error: error != nil) + ">\(optionsHTML)</select>"
        return fieldShell(id: id, label: label, optional: optional, control: control, help: help, helpHTML: helpHTML, error: error, hint: nil, cls: cls)
    }

    /// A checkbox wrapped in its label (`<label class="ck"><input …> Label</label>`), with optional help below.
    static func checkbox(_ name: String, value: String = "1", label: String, checked: Bool = false, disabled: Bool = false, required: Bool = false,
                         help: String? = nil, labelHTML: String? = nil) -> String {
        "<label class=\"ck\"><input type=\"checkbox\" name=\"\(esc(name))\" value=\"\(esc(value))\"\(checked ? " checked" : "")\(disabled ? " disabled" : "")\(required ? " required" : "")> \(labelHTML ?? esc(label))</label>"
            + (help.map { "<p class=\"help\">\($0.isEmpty ? "" : esc($0))</p>" } ?? "")
    }

    struct Choice: Sendable {
        var value: String
        var label: String
        var help: String?
        var tone: Tone?
        init(_ value: String, _ label: String, help: String? = nil, tone: Tone? = nil) { self.value = value; self.label = label; self.help = help; self.tone = tone }
    }

    /// Radio buttons as option cards inside a fieldset (decisions, kinds). `tone: .danger` marks a destructive choice.
    static func choices(_ name: String, legend: String, legendHTML: String? = nil, _ choices: [Choice], selected: String? = nil, required: Bool = false,
                        help: String? = nil, disabled: Bool = false) -> String {
        let items = choices.map { c in
            "<label class=\"choice\(c.tone.map { " " + $0.cls } ?? "")\"><input type=\"radio\" name=\"\(esc(name))\" value=\"\(esc(c.value))\"\(c.value == selected ? " checked" : "")\(required ? " required" : "")\(disabled ? " disabled" : "")>"
                + "<span><strong>\(esc(c.label))</strong>\(c.help.map { "<span class=\"help\">\(esc($0))</span>" } ?? "")</span></label>"
        }.joined()
        return "<fieldset><legend>\(legendHTML ?? esc(legend))</legend>\(help.map { "<p class=\"help\">\(esc($0))</p>" } ?? "")<div class=\"choices\">\(items)</div></fieldset>"
    }

    static func fieldset(_ legend: String, help: String? = nil, _ html: String) -> String {
        "<fieldset><legend>\(esc(legend))</legend>\(help.map { "<p class=\"help\">\(esc($0))</p>" } ?? "")\(html)</fieldset>"
    }

    /// The recorded reason every operator change and most destructive actions need (8 to 300 characters, matching the server's rule).
    static func reason(id: String, name: String = "reason", label: String = "Reason", required: Bool = true, help: String? = "Recorded in the audit log with your name.",
                       multiline: Bool = false, placeholder: String? = nil, minLength: Int = 8, maxLength: Int = 300) -> String {
        var attrs = ["maxlength": String(maxLength)]
        if required, minLength > 0 { attrs["minlength"] = String(minLength) }
        return multiline
            ? textarea(name, label: label, id: id, placeholder: placeholder, help: help, required: required, optional: !required, attrs: attrs)
            : input(name, label: label, id: id, placeholder: placeholder, help: help, required: required, optional: !required, attrs: attrs)
    }

    /// The row of buttons at the end of a form. `sep` draws a rule above (long forms).
    static func formActions(_ html: String, sep: Bool = false) -> String {
        "<div class=\"form-actions\(sep ? " sep" : "")\">\(html)</div>"
    }

    // MARK: - Surfaces

    /// A card: optional title (h2), description and header actions, then the body markup.
    static func card(_ title: String? = nil, id: String? = nil, description: String? = nil, descriptionHTML: String? = nil, actions: String = "",
                     tone: Tone? = nil, cls: String? = nil, titleHTML: String? = nil, _ html: String) -> String {
        var out = "<section class=\"card\(tone.map { " " + $0.cls } ?? "")\(cls.map { " " + $0 } ?? "")\"\(id.map { " id=\"\(esc($0))\"" } ?? "")>"
        if title != nil || titleHTML != nil {
            let d = descriptionHTML.map { "<p class=\"d\">\($0)</p>" } ?? description.map { "<p class=\"d\">\(esc($0))</p>" } ?? ""
            out += "<header class=\"card-h\"><div><h2>\(titleHTML ?? esc(title ?? ""))</h2>\(d)</div>\(actions.isEmpty ? "" : "<div class=\"a\">\(actions)</div>")</header>"
        }
        return out + html + "</section>"
    }

    /// A card without a header (a table or a form that the page heading already names).
    static func panel(_ html: String, cls: String? = nil) -> String { "<section class=\"card\(cls.map { " " + $0 } ?? "")\">\(html)</section>" }

    /// A colour sample next to its hex value. Drawn with an SVG `fill` presentation attribute (not a style attribute, so the CSP holds);
    /// anything other than a validated `#RRGGBB` is shown as escaped text only.
    static func swatch(_ hex: String) -> String {
        guard hex.range(of: "^#[0-9A-Fa-f]{6}$", options: .regularExpression) != nil else { return esc(hex) }
        return "<span class=\"sw\"><svg viewBox=\"0 0 16 16\" aria-hidden=\"true\" focusable=\"false\"><rect width=\"16\" height=\"16\" rx=\"4\" fill=\"\(hex)\"/></svg><code>\(hex)</code></span>"
    }

    /// A heading for a group of cards.
    static func sectionTitle(_ title: String, description: String? = nil) -> String {
        "<div class=\"sec\"><h2>\(esc(title))</h2>\(description.map { "<p>\(esc($0))</p>" } ?? "")</div>"
    }

    /// A card in the danger tone for irreversible actions.
    static func dangerZone(_ title: String, description: String, _ html: String) -> String {
        card(title, description: description, tone: .danger, html)
    }

    struct Stat: Sendable {
        var value: String
        var label: String
        var hint: String?
        var tone: Tone?
        var href: String?
        init(_ value: String, _ label: String, hint: String? = nil, tone: Tone? = nil, href: String? = nil) {
            self.value = value; self.label = label; self.hint = hint; self.tone = tone; self.href = href
        }
    }

    /// A key number. Markup `<div class="n">value</div><div class="l">label</div>` (stable: tests and other pages read it).
    static func stat(_ s: Stat) -> String {
        let inner = "<div class=\"n\">\(esc(s.value))</div><div class=\"l\">\(esc(s.label))</div>\(s.hint.map { "<div class=\"h\">\(esc($0))</div>" } ?? "")"
        let cls = "stat\(s.tone.map { " " + $0.cls } ?? "")"
        if let href = s.href { return "<a class=\"\(cls)\" href=\"\(esc(href))\">\(inner)</a>" }
        return "<div class=\"\(cls)\">\(inner)</div>"
    }

    static func stats(_ items: [Stat]) -> String { "<div class=\"kpis\">\(items.map(stat).joined())</div>" }

    /// Label and value pairs. Labels are text; values are markup.
    static func keyValues(_ rows: [(String, String)]) -> String {
        "<dl class=\"kv\">" + rows.map { "<dt>\(esc($0.0))</dt><dd>\($0.1)</dd>" }.joined() + "</dl>"
    }

    /// An inline message. Status messages are announced (`role="status"`; `urgent` uses `alert`).
    static func callout(_ tone: Tone, title: String? = nil, urgent: Bool = false, _ html: String) -> String {
        let glyph: Icon = switch tone {
        case .danger: .error
        case .warning: .alert
        case .success: .check
        default: .info
        }
        return "<div class=\"callout \(tone.cls)\" role=\"\(urgent ? "alert" : "status")\">\(icon(glyph))<div>\(title.map { "<p class=\"t\">\(esc($0))</p>" } ?? "")\(html)</div></div>"
    }

    /// The flash message after a redirect (`?m=…`): announced, styled as a toast at the top of the page.
    static func toast(_ message: String, tone: Tone = .success) -> String {
        "<div class=\"toast \(tone.cls)\" role=\"status\">\(icon(tone == .danger ? .error : (tone == .warning ? .alert : .check)))<p>\(esc(message))</p></div>"
    }

    /// An empty state: what is missing, why it matters, and the next step.
    static func empty(_ title: String, _ message: String? = nil, icon: Icon = .info, action: String = "") -> String {
        "<div class=\"empty\">\(self.icon(icon))<p class=\"t\">\(esc(title))</p>\(message.map { "<p>\(esc($0))</p>" } ?? "")\(action.isEmpty ? "" : "<div class=\"row\">\(action)</div>")</div>"
    }

    struct Step: Sendable {
        var done: Bool
        var title: String
        var detailHTML: String
        init(_ done: Bool, _ title: String, _ detailHTML: String) { self.done = done; self.title = title; self.detailHTML = detailHTML }
    }

    /// A checklist with progress; the first open step is highlighted as the next one.
    static func checklist(_ steps: [Step], label: String) -> String {
        let done = steps.filter(\.done).count
        let next = steps.firstIndex { !$0.done }
        let items = steps.enumerated().map { index, step in
            let mark = step.done ? icon(.check) : String(index + 1)
            let cls = step.done ? " class=\"done\"" : (index == next ? " class=\"now\"" : "")
            return "<li\(cls)><span class=\"dot\" aria-hidden=\"true\">\(mark)</span><div><p class=\"ct\">\(esc(step.title)) <span class=\"vh\">\(step.done ? "(done)" : (index == next ? "(next step)" : "(to do)"))</span></p><p class=\"cd\">\(step.detailHTML)</p></div></li>"
        }.joined()
        return "<div class=\"progress\"><span><strong>\(done) of \(steps.count)</strong> complete</span><progress max=\"\(steps.count)\" value=\"\(done)\" aria-label=\"\(esc(label)): \(done) of \(steps.count) complete\"></progress></div><ol class=\"checklist\" aria-label=\"\(esc(label))\">\(items)</ol>"
    }

    /// A destructive action behind a disclosure: the first click opens a short confirmation with the real submit button (no script).
    static func confirm(_ label: String, ariaLabel: String? = nil, style: ButtonStyle = .danger, small: Bool = true, _ html: String) -> String {
        "<details class=\"confirm\"><summary class=\"\(style.cls)\(small ? " sm" : "")\"\(ariaLabel.map { " aria-label=\"\(esc($0))\"" } ?? "")>\(esc(label))</summary><div class=\"confirm-pop\">\(html)</div></details>"
    }

    /// Extra detail folded away by default.
    static func more(_ summary: String, _ html: String) -> String {
        "<details class=\"more\"><summary>\(esc(summary))</summary>\(html)</details>"
    }

    /// A vertical history (review decisions, notes). Each entry: title (markup), meta line (text), body (markup).
    static func timeline(_ entries: [(titleHTML: String, meta: String, bodyHTML: String)], label: String) -> String {
        "<ol class=\"timeline\" aria-label=\"\(esc(label))\">" + entries.map {
            "<li><p class=\"m\">\(esc($0.meta))</p><p><strong>\($0.titleHTML)</strong></p>\($0.bodyHTML.isEmpty ? "" : "<p>\($0.bodyHTML)</p>")</li>"
        }.joined() + "</ol>"
    }

    /// A side-by-side line diff. Lines only in `before` are marked removed, lines only in `after` added; each mark is also spoken.
    static func diff(before: [String]?, after: [String], beforeTitle: String, afterTitle: String) -> String {
        func pane(_ title: String, _ lines: [String], marked: Set<String>, cls: String, word: String) -> String {
            let count = lines.filter { marked.contains($0) }.count
            let items = lines.map { line in
                marked.contains(line) ? "<li class=\"\(cls)\"><span class=\"vh\">\(word): </span>\(esc(line))</li>" : "<li>\(esc(line))</li>"
            }.joined()
            return "<figure><figcaption><span>\(esc(title))</span><span class=\"mu\">\(count) \(word.lowercased())</span></figcaption><ol class=\"code\">\(items)</ol></figure>"
        }
        guard let before else { return "<div class=\"diff\">\(pane(afterTitle, after, marked: [], cls: "add", word: "Added"))</div>" }
        let old = Set(before), new = Set(after)
        return "<div class=\"diff\">\(pane(beforeTitle, before, marked: old.subtracting(new), cls: "del", word: "Removed"))\(pane(afterTitle, after, marked: new.subtracting(old), cls: "add", word: "Added"))</div>"
    }

    /// Pretty-printed, key-sorted JSON lines (for diffs and payload views); the raw text when it does not parse.
    static func jsonLines(_ json: String) -> [String] {
        guard let object = try? JSONSerialization.jsonObject(with: Data(json.utf8)),
              let pretty = try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys]) else { return [json] }
        return String(decoding: pretty, as: UTF8.self).split(separator: "\n").map(String.init)
    }

    /// A sandboxed preview in a device frame (the document has its own CSP; `sandbox=""` gives it an opaque origin and no script).
    static func preview(src: String, title: String, width: Int, height: Int) -> String {
        "<div class=\"device\"><iframe title=\"\(esc(title))\" src=\"\(esc(src))\" sandbox=\"\" referrerpolicy=\"no-referrer\" width=\"\(width)\" height=\"\(height)\" loading=\"lazy\"></iframe></div>"
    }

    // MARK: - Data tables

    enum SortValue: Sendable {
        case text(String), number(Double), date(Date)

        static func less(_ a: SortValue?, _ b: SortValue?) -> Bool? {
            switch (a, b) {
            case (.number(let x)?, .number(let y)?): return x == y ? nil : x < y
            case (.date(let x)?, .date(let y)?): return x == y ? nil : x < y
            case (.text(let x)?, .text(let y)?):
                let order = x.compare(y, options: [.caseInsensitive, .numeric])
                return order == .orderedSame ? nil : order == .orderedAscending
            case (nil, nil): return nil
            case (nil, _): return false
            case (_, nil): return true
            default: return nil
            }
        }
    }

    struct Cell: Sendable {
        var html: String
        var sort: SortValue?
        init(html: String, sort: SortValue? = nil) { self.html = html; self.sort = sort }
        static func text(_ text: String) -> Cell { Cell(html: ConsoleUI.esc(text), sort: .text(text)) }
        static func number(_ value: Int) -> Cell { Cell(html: String(value), sort: .number(Double(value))) }
        static func date(_ date: Date?) -> Cell { Cell(html: date.map(DashboardFormat.date) ?? "—", sort: date.map { .date($0) }) }
        static func html(_ html: String, sort: SortValue? = nil) -> Cell { Cell(html: html, sort: sort) }
    }

    struct Column: Sendable {
        var title: String
        /// Set to make the column sortable (the query value, so keep it short and stable).
        var key: String?
        var numeric: Bool
        /// Right-aligned actions column (an empty title is spoken as "Actions").
        var actions: Bool
        init(_ title: String, key: String? = nil, numeric: Bool = false, actions: Bool = false) {
            self.title = title; self.key = key; self.numeric = numeric; self.actions = actions
        }
    }

    /// Sorting and paging of one table, read from the page's query string (`<id>_sort`, `<id>_dir`, `<id>_page`) so every link works without
    /// script. Other query parameters are kept; one-time flash parameters are dropped.
    struct TableState: Sendable {
        var id: String
        var path: String
        var query: [URLQueryItem]
        var sort: String?
        var ascending: Bool
        var page: Int

        static let flashKeys: Set<String> = ["m", "im", "lm", "sm"]

        init(id: String, path: String, query: [URLQueryItem], defaultSort: String? = nil, defaultAscending: Bool = true) {
            self.id = id
            self.path = path
            self.query = query.filter { !Self.flashKeys.contains($0.name) }
            func value(_ name: String) -> String? { query.last { $0.name == name }?.value }
            let requested = value("\(id)_sort").flatMap { $0.isEmpty ? nil : $0 }
            sort = requested ?? defaultSort
            ascending = requested == nil ? defaultAscending : value("\(id)_dir") != "desc"
            page = max(1, Int(value("\(id)_page") ?? "") ?? 1)
        }

        init(_ req: Request, id: String, defaultSort: String? = nil, defaultAscending: Bool = true) {
            let items = URLComponents(string: "?" + (req.url.query ?? ""))?.queryItems ?? []
            self.init(id: id, path: req.url.path, query: items, defaultSort: defaultSort, defaultAscending: defaultAscending)
        }

        /// A same-page link with this table's parameters replaced.
        func href(sort: String? = nil, ascending: Bool? = nil, page: Int? = nil) -> String {
            let mine: Set<String> = ["\(id)_sort", "\(id)_dir", "\(id)_page"]
            var items = query.filter { !mine.contains($0.name) }
            if let key = sort ?? self.sort {
                items.append(URLQueryItem(name: "\(id)_sort", value: key))
                items.append(URLQueryItem(name: "\(id)_dir", value: (ascending ?? self.ascending) ? "asc" : "desc"))
            }
            let target = page ?? 1
            if target > 1 { items.append(URLQueryItem(name: "\(id)_page", value: String(target))) }
            var components = URLComponents()
            components.path = path.hasPrefix("/") && !path.hasPrefix("//") ? path : "/"
            components.queryItems = items.isEmpty ? nil : items
            return components.string ?? path
        }
    }

    /// A data table: caption (spoken), column headers with `scope`, sortable headers as links (`aria-sort` on the sorted one), numeric columns
    /// right-aligned, an empty state, and pagination when `state` is given and the rows exceed `pageSize`.
    static func table(_ columns: [Column], _ rows: [[Cell]], caption: String, state: TableState? = nil, pageSize: Int = 25,
                      empty: String = "Nothing here yet.", emptyMessage: String? = nil, emptyAction: String = "") -> String {
        guard !rows.isEmpty else { return self.empty(empty, emptyMessage, action: emptyAction) }
        var rows = rows
        if let state, let key = state.sort, let index = columns.firstIndex(where: { $0.key == key }) {
            rows = rows.enumerated().sorted { a, b in
                let x = index < a.element.count ? a.element[index].sort : nil
                let y = index < b.element.count ? b.element[index].sort : nil
                if let less = SortValue.less(x, y) { return state.ascending ? less : !less }
                return a.offset < b.offset
            }.map(\.element)
        }
        let total = rows.count
        var pager = ""
        if let state, pageSize > 0, total > pageSize {
            let pages = (total + pageSize - 1) / pageSize
            let page = min(state.page, pages)
            rows = Array(rows[((page - 1) * pageSize)..<min(total, page * pageSize)])
            let prev = page > 1 ? "<a class=\"btn s sm\" rel=\"prev\" href=\"\(esc(state.href(page: page - 1)))\">Previous</a>" : "<span class=\"btn s sm\" aria-disabled=\"true\">Previous</span>"
            let next = page < pages ? "<a class=\"btn s sm\" rel=\"next\" href=\"\(esc(state.href(page: page + 1)))\">Next</a>" : "<span class=\"btn s sm\" aria-disabled=\"true\">Next</span>"
            pager = "<nav class=\"pager\" aria-label=\"\(esc(caption)): pages\">\(prev)<span>Page \(page) of \(pages) · \(total) rows</span>\(next)</nav>"
        }
        let head = columns.map { column -> String in
            let cls = column.numeric ? " class=\"num\"" : (column.actions ? " class=\"act\"" : "")
            guard !column.title.isEmpty else { return "<th scope=\"col\"\(cls)><span class=\"vh\">Actions</span></th>" }
            guard let state, let key = column.key else { return "<th scope=\"col\"\(cls)>\(esc(column.title))</th>" }
            let sorted = state.sort == key
            let nextAscending = sorted ? !state.ascending : true
            let glyph = sorted ? icon(state.ascending ? .sortUp : .sortDown) : icon(.sort)
            let spoken = sorted ? "<span class=\"vh\"> (sorted \(state.ascending ? "ascending" : "descending"))</span>" : ""
            return "<th scope=\"col\"\(cls)\(sorted ? " aria-sort=\"\(state.ascending ? "ascending" : "descending")\"" : "")><a class=\"sort\" href=\"\(esc(state.href(sort: key, ascending: nextAscending)))\">\(esc(column.title))\(spoken)\(glyph)</a></th>"
        }.joined()
        let body = rows.map { row in
            "<tr>" + row.enumerated().map { index, cell in
                let column = index < columns.count ? columns[index] : nil
                let cls = column?.numeric == true ? " class=\"num\"" : (column?.actions == true ? " class=\"act\"" : "")
                return "<td\(cls)>\(cell.html)</td>"
            }.joined() + "</tr>"
        }.joined()
        return "<div class=\"tw\"><table><caption class=\"vh\">\(esc(caption))</caption><thead><tr>\(head)</tr></thead><tbody>\(body)</tbody></table></div>\(pager)"
    }

    // MARK: - Navigation helpers

    /// A same-origin path from the `Referer` header for a "go back" link, or nil. Only a relative path inside `prefix` is accepted (no scheme,
    /// no host, no `//`), so the link can never lead off the console.
    static func backPath(referer: String?, host: String?, prefix: String) -> String? {
        guard let referer, let url = URLComponents(string: referer) else { return nil }
        if let refererHost = url.host { guard let host, refererHost.lowercased() == host.lowercased().split(separator: ":").first.map(String.init) else { return nil } }
        let path = url.percentEncodedPath
        guard path == prefix || path.hasPrefix(prefix + "/"), !path.hasPrefix("//"), !path.contains("\\") else { return nil }
        var components = URLComponents()
        components.percentEncodedPath = path
        components.percentEncodedQuery = url.percentEncodedQuery
        return components.string
    }
}
