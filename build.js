// Builds docs/sign.html and docs/verify.html, each fully self-contained,
// plus docs/index.html (a copy of the sign page) for GitHub Pages.
// Usage: node build.js
const fs = require('fs');
const path = require('path');
const rd = (...p) => fs.readFileSync(path.join(__dirname, ...p), 'utf8');

const srcDir = path.join(__dirname, 'src');
const core = fs.readdirSync(srcDir).filter((f) => f.endsWith('.js')).sort().map((f) => rd('src', f)).join('\n');
// Stripe images (made by tools/stripes.py) are embedded as data URIs.
const dataUri = (f) => 'data:image/png;base64,' + fs.readFileSync(path.join(__dirname, 'pages', f)).toString('base64');
const css = rd('pages', 'style.css').split('__HIDE_PNG__').join(dataUri('hide.png'));
const common = rd('pages', 'common.js');

fs.mkdirSync(path.join(__dirname, 'docs'), { recursive: true });
for (const page of ['sign', 'verify']) {
  const js = [core, common, rd('pages', page + '.js')].join('\n');
  if (/<\/script/i.test(js)) throw new Error('script contains </script');
  const html = rd('pages', page + '.html')
    .replace('/*__CSS__*/', () => css)
    .replace('__FAVICON_PNG__', () => dataUri('favicon.png'))
    .replace('/*__CORE__*/\n/*__COMMON__*/\n/*__PAGE__*/', () => js);
  if (/\/\*__|__[A-Z_]+_PNG__/.test(html)) throw new Error('unfilled placeholder in ' + page);
  fs.writeFileSync(path.join(__dirname, 'docs', page + '.html'), html);
  if (page === 'sign') fs.writeFileSync(path.join(__dirname, 'docs', 'index.html'), html);
  console.log(`docs/${page}.html  ${(html.length / 1024).toFixed(1)} KB`);
}
