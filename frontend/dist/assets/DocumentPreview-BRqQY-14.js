import{j as e}from"./vendor-state-BjT_zREg.js";import{p as o,X as x,d as g}from"./vendor-ui-CaTPr3iI.js";const h=({status:t})=>{switch(t){case"signed":return e.jsx(g,{className:"w-4 h-4 text-green-500"});case"declined":return e.jsx(x,{className:"w-4 h-4 text-red-500"});default:return e.jsx(o,{className:"w-4 h-4 text-yellow-500"})}},m=({signature:t})=>{const n={pending:"border-yellow-500/30 bg-yellow-500/5",signed:"border-green-500/30 bg-green-500/5",declined:"border-red-500/30 bg-red-500/5"};return e.jsxs("div",{className:`border-2 rounded-lg p-4 ${n[t.status]}`,style:{minWidth:"280px"},children:[e.jsxs("div",{className:"flex items-center justify-between mb-3",children:[e.jsxs("span",{className:"text-sm font-medium text-gray-700",children:[t.signerType==="client"?"Client":"Provider"," - ",t.signerRole]}),e.jsxs("div",{className:"flex items-center gap-1",children:[e.jsx(h,{status:t.status}),e.jsx("span",{className:`text-xs font-medium ${t.status==="signed"?"text-green-600":t.status==="declined"?"text-red-600":"text-yellow-600"}`,children:t.status==="signed"?"Signed":t.status==="declined"?"Declined":"Pending"})]})]}),t.status==="signed"&&t.signatureImage?e.jsxs("div",{className:"space-y-2",children:[e.jsx("div",{className:"bg-white border border-gray-200 rounded p-2",children:e.jsx("img",{src:t.signatureImage,alt:`Signature of ${t.signerName}`,className:"max-h-16 mx-auto"})}),e.jsxs("div",{className:"text-sm",children:[e.jsx("p",{className:"font-medium text-gray-800",children:t.signerName}),e.jsx("p",{className:"text-gray-500 text-xs",children:t.signerEmail}),t.signedAt&&e.jsxs("p",{className:"text-gray-400 text-xs mt-1",children:["Signed: ",new Date(t.signedAt).toLocaleString()]})]})]}):t.status==="declined"?e.jsxs("div",{className:"text-sm",children:[e.jsx("p",{className:"text-gray-500",children:t.signerEmail}),e.jsx("p",{className:"text-red-500 text-xs mt-1",children:"This signer has declined to sign."})]}):e.jsxs("div",{className:"space-y-2",children:[e.jsx("div",{className:"h-16 border-b-2 border-dashed border-gray-300 flex items-end justify-center pb-1",children:e.jsx("span",{className:"text-gray-400 text-xs",children:"Signature"})}),e.jsxs("div",{className:"text-sm text-gray-500",children:[e.jsx("p",{children:t.signerEmail}),e.jsx("p",{className:"text-xs text-gray-400 mt-1",children:"Awaiting signature"})]})]})]})},j=({contentHtml:t,signatures:n=[],showSignatureBlocks:c=!0,className:l=""})=>{const r=n.map(s=>({signerType:s.signer_type,signerRole:s.signer_role,signerName:s.signer_name,signerEmail:s.signer_email,status:s.status,signedAt:s.signed_at,signatureImage:s.signature_image})),a=r.filter(s=>s.signerType==="client"),d=r.filter(s=>s.signerType==="provider");return e.jsxs("div",{className:`document-preview ${l}`,children:[e.jsxs("div",{className:"bg-white text-gray-900 p-8 rounded-lg shadow-lg prose prose-sm max-w-none",style:{fontFamily:'Georgia, "Times New Roman", Times, serif',lineHeight:1.6},children:[e.jsx("div",{dangerouslySetInnerHTML:{__html:t},className:"document-content"}),c&&r.length>0&&e.jsxs("div",{className:"mt-8 pt-8 border-t border-gray-200",children:[e.jsx("h3",{className:"text-lg font-semibold mb-6 text-gray-800",children:"Signatures"}),e.jsxs("div",{className:"grid grid-cols-1 md:grid-cols-2 gap-6",children:[a.length>0&&e.jsxs("div",{children:[e.jsx("h4",{className:"text-sm font-medium text-gray-600 mb-3 uppercase tracking-wide",children:"Client"}),e.jsx("div",{className:"space-y-4",children:a.map((s,i)=>e.jsx(m,{signature:s},`client-${i}`))})]}),d.length>0&&e.jsxs("div",{children:[e.jsx("h4",{className:"text-sm font-medium text-gray-600 mb-3 uppercase tracking-wide",children:"Provider"}),e.jsx("div",{className:"space-y-4",children:d.map((s,i)=>e.jsx(m,{signature:s},`provider-${i}`))})]})]})]})]}),e.jsx("style",{children:`
        .document-content h1 {
          font-size: 1.5rem;
          font-weight: 700;
          margin-bottom: 1rem;
          text-align: center;
        }
        .document-content h2 {
          font-size: 1.25rem;
          font-weight: 600;
          margin-top: 1.5rem;
          margin-bottom: 0.75rem;
          border-bottom: 1px solid #e5e7eb;
          padding-bottom: 0.25rem;
        }
        .document-content h3 {
          font-size: 1rem;
          font-weight: 600;
          margin-top: 1rem;
          margin-bottom: 0.5rem;
        }
        .document-content p {
          margin-bottom: 0.75rem;
        }
        .document-content ul, .document-content ol {
          margin-left: 1.5rem;
          margin-bottom: 0.75rem;
        }
        .document-content li {
          margin-bottom: 0.25rem;
        }
        .document-content table {
          width: 100%;
          border-collapse: collapse;
          margin: 1rem 0;
        }
        .document-content th, .document-content td {
          border: 1px solid #e5e7eb;
          padding: 0.5rem;
          text-align: left;
        }
        .document-content th {
          background-color: #f9fafb;
          font-weight: 600;
        }
        .document-content .placeholder {
          background-color: #fef3c7;
          padding: 0 0.25rem;
          border-radius: 0.125rem;
        }
      `})]})};export{j as D};
