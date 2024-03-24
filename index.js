import functions from '@google-cloud/functions-framework'
import { webcrypto as crypto } from 'crypto'

const DISCORD_WEBHOOK_ID = process.env.DISCORD_WEBHOOK_ID
const DISCORD_WEBHOOK_TOKEN = process.env.DISCORD_WEBHOOK_TOKEN
const GITHUB_SECRET = process.env.GITHUB_SECRET
const USER_DEPENDABOT = 49699333

/**
 * HTTP function that filters Github events and relays the rest to Discord.
 *
 * @param {Object} req Cloud Function request context.
 * @param {Object} res Cloud Function response context.
 */
functions.http('handleRequest', async (req, res) => {
  // Expect a POST request.
  if ( req.method !== 'POST' ) {
    // "Method Not Allowed"
    res.status(405).send()
    return
  }

  // Verify the request has the expected signature.
  const expectedSignature = req.get('X-Hub-Signature-256') || ''
  const data = req.rawBody
  let enc = new TextEncoder()
  const key = await crypto.subtle.importKey('raw', enc.encode(GITHUB_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const rawSig = await crypto.subtle.sign('HMAC', key, enc.encode(data))
  const actualSignature = 'sha256=' + (new Uint8Array(rawSig).reduce((a, b) => a + b.toString(16).padStart(2, '0'), ''))

  if ( expectedSignature !== actualSignature ) {
    // "Unauthorized"
    res.status(401).send()
    return
  }

  // Since the request body was retrieved as text the JSON must be parsed.
  const jsonData = req.body
  const event = req.get('X-GitHub-Event')

  // Filter out unwanted Discord messages from GitHub to reduce spam and filter out GitHub events Discord is known to ignore to reduce rate-limiting.
  if (!(
    // Ignore "GitHub Actions checks success..." and as well as the Discord ignored non-completed check_suite events.
    (event === 'check_suite' && (jsonData.status !== 'completed' || jsonData.check_suite.conclusion === 'success')) ||
    // Ignore "Repo Sync success..." and as well as the Discord ignored non-completed check_run events.
    (event === 'check_run' && (jsonData.status !== 'completed' || (jsonData.check_run.name === 'Repo Sync' && jsonData.check_run.conclusion === 'success'))) ||
    // Ignore Dependabot branch creation and deletion.
    ((event === 'create' || event === 'delete') && jsonData.ref_type === 'branch' && jsonData.sender.id === USER_DEPENDABOT) ||
    // Ignore Repo Sync push for localisation updates.
    (event === 'push' && jsonData.ref === 'refs/heads/weirdgloop/repo-sync' && jsonData.commits.every((e) => e.committer.email === 'l10n-bot@translatewiki.net')) ||
    // Ignore workflow events as Discord already ignores them.
    event === 'workflow_job' || event === 'workflow_run'
  )) {
    // Forward the GitHub webhook data to the Discord webhook.
    const discord = await fetch(`https://discord.com/api/webhooks/${DISCORD_WEBHOOK_ID}/${DISCORD_WEBHOOK_TOKEN}/github`, {
      method: 'POST',
      body: data,
      headers: req.headers,
    })
    res.status(discord.status).set(Object.fromEntries(discord.headers)).send(await discord.text())
  } else {
    // Otherwise, this request has been filtered out.
    // "No Content"
    res.status(204).send()
  }
})