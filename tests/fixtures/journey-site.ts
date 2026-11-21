import type { IncomingMessage, ServerResponse } from 'node:http';
import type { FixtureServer } from './server.js';

/**
 * A fake store whose cart and checkout need a session cookie:
 *
 *   /login          form (#user, #pass, #login) posting to /do-login
 *   /do-login       user "tester" + password PASSWORD sets the session cookie, anything else redirects back
 *   /account        logged in only
 *   /cart           logged in only; links to /checkout (#to-checkout) and to another site (#offsite)
 *   /checkout       logged in only; loads pay-loggedin.js (a script only a logged-in visitor sees) and has a
 *                   payment form (card field, #pay) posting to /pay
 *   /pay            records every POST in `state.payPosts`
 *
 * Plain visitors are redirected to /login and never see the checkout script.
 */

export const JOURNEY_PASSWORD = 'correct-horse-battery';
export const SESSION_COOKIE = 'session=sess-7f3a9c';

export interface JourneySiteState {
  /** Bodies of POST /do-login. */
  loginBodies: string[];
  payPosts: string[];
}

function loggedIn(req: IncomingMessage): boolean {
  return (req.headers.cookie ?? '').split(/;\s*/).includes(SESSION_COOKIE);
}

export function installJourneySite(server: FixtureServer): JourneySiteState {
  const shop = 'shop.test';
  const state: JourneySiteState = { loginBodies: [], payPosts: [] };
  const vendor = (path: string): string => `http://cdn.vendor-a.test:{port}${path}`;
  const page = (title: string, body: string, head = ''): string =>
    `<!doctype html><html><head><title>${title}</title>${head}</head><body>${body}</body></html>`;
  const html = (res: ServerResponse, body: string): void => {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }).end(body.replaceAll('{port}', String(server.port)));
  };
  const redirect = (res: ServerResponse, to: string, extra: Record<string, string> = {}): void => {
    res.writeHead(302, { location: to, 'cache-control': 'no-store', ...extra }).end();
  };
  const guarded = (body: string): ((req: IncomingMessage, res: ServerResponse) => void) => (req, res) => {
    if (!loggedIn(req)) redirect(res, '/login');
    else html(res, body);
  };

  server.set(shop, '/login', {
    handler: (_req, res) =>
      html(
        res,
        page(
          'Login',
          `<form action="/do-login" method="post"><input id="user" name="user"><input id="pass" name="pass" type="password"><button id="login" type="submit">Log in</button></form>`,
          `<script src="${vendor('/login-widget.js')}"></script>`,
        ),
      ),
  });
  server.js('cdn.vendor-a.test', '/login-widget.js', 'window.LoginWidget = 1;\n');
  server.set(shop, '/do-login', {
    handler: (_req, res, body) => {
      state.loginBodies.push(body);
      const params = new URLSearchParams(body);
      if (params.get('user') === 'tester' && params.get('pass') === JOURNEY_PASSWORD) {
        redirect(res, '/account', { 'set-cookie': `${SESSION_COOKIE}; Path=/; HttpOnly` });
      } else {
        redirect(res, '/login?error=1');
      }
    },
  });
  server.set(shop, '/account', {
    handler: guarded(page('Account', '<h1>Account</h1><a href="/cart">Cart</a>', `<script>window.accountPage = true;</script>`)),
  });
  server.set(shop, '/cart', {
    handler: guarded(
      page(
        'Cart',
        `<h1>Cart</h1><a id="to-checkout" href="/checkout">Checkout</a> <a id="offsite" href="http://cdn.vendor-a.test:{port}/elsewhere.html">Elsewhere</a>`,
        `<script src="${vendor('/cart-widget.js')}"></script>`,
      ),
    ),
  });
  server.js('cdn.vendor-a.test', '/cart-widget.js', 'window.CartWidget = 1;\n');
  server.html('cdn.vendor-a.test', '/elsewhere.html', '<!doctype html><title>elsewhere</title>');
  server.set(shop, '/checkout', {
    handler: guarded(
      page(
        'Checkout',
        `<h1>Checkout</h1><form action="/pay" method="post"><input name="cardnumber" autocomplete="cc-number"><button id="pay" type="submit">Pay now</button></form>`,
        `<script src="${vendor('/pay-loggedin.js')}"></script>`,
      ),
    ),
  });
  server.js('cdn.vendor-a.test', '/pay-loggedin.js', 'window.PayLoggedIn = { mount: function () {} };\n');
  server.set(shop, '/pay', {
    handler: (_req, res, body) => {
      state.payPosts.push(body);
      html(res, page('Paid', '<h1>Paid</h1>'));
    },
  });
  // Public pages (plain scan) of the same site.
  server.html(shop, '/', page('Home', '<h1>Home</h1>', `<script src="${vendor('/login-widget.js')}"></script>`));
  return state;
}
