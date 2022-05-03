addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})
/**
 * Respond with hello worker text
 * @param {Request} request
 */
async function handleRequest(request) {
  // Expect a POST request.
  if ( request.method !== 'POST' ) {
    return new Response(null, {
      status: 405,
      statusText: 'Method Not Allowed',
    })
  }

  // Verify the request has the expected signature.
  const expectedSignature = request.headers.get('X-Hub-Signature-256') || ''
  const data = await request.clone().text()
  let enc = new TextEncoder()
  const key = await crypto.subtle.importKey('raw', enc.encode(GITHUB_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const rawSig = await crypto.subtle.sign('HMAC', key, enc.encode(data))
  const actualSignature = 'sha256=' + (new Uint8Array(rawSig).reduce((a, b) => a + b.toString(16).padStart(2, '0'), ''))

  if ( expectedSignature !== actualSignature ) {
    return new Response(null, {
      status: 401,
      statusText: 'Unauthorized',
    })
  }

  // Since the request body was retrieved as text the JSON must be parsed.
  const jsonData = JSON.parse(data)
  const event = request.headers.get('X-GitHub-Event')

  if (!(
    // Ignore "GitHub Actions checks success..."
    event === 'check_suite' && jsonData.check_suite.conclusion === 'success' ||
    // Ignore "Repo Sync success..."
    event === 'check_run' && jsonData.check_run.name === 'Repo Sync' && jsonData.check_run.conclusion === 'success'
  )) {
    // Forward the GitHub webhook data to the Discord webhook.
    return fetch(`https://discord.com/api/webhooks/${DISCORD_WEBHOOK_ID}/${DISCORD_WEBHOOK_TOKEN}/github`, request)
  } else {
    // Otherwise, this request has been filtered out.
    return new Response(null, {
      status: 204,
      statusText: 'No Content',
    })
  }
}
