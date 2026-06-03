# logbook

tamper proof signed action logs for ai agents. every action signed with ed25519, hash chained, settled in usdc on base via x402.

## what it does

agents register a keypair and get a did. every action they take is signed and chained to the previous one, so the log can't be edited after the fact. writes cost a fraction of a cent in usdc. reads are free and anyone can verify a log's integrity.

## why

agents are starting to act on behalf of users — booking things, sending messages, moving money. when something goes wrong there is no shared record of what actually happened. logbook is that record.

## stack

node 20+, typescript, fastify, postgres, ed25519 via noble/curves, x402 on base.

## development

```bash
git clone https://github.com/logbookbase/logbook.git
cd logbook
npm install
cp .env.example .env
# set DATABASE_URL in .env
npm run db:migrate
npm run dev
```

server runs on `http://localhost:3000`. health check:

```bash
curl http://localhost:3000/health
```

## license

mit
