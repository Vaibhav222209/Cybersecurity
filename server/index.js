import { createPlatform } from './platform.js';

const port = Number(process.env.PORT || 3001);
const platform = createPlatform({
  dbPath: process.env.DB_PATH || 'data/aegis.db',
  demo: process.env.DEMO_MODE !== 'false',
});

try {
  const address = await platform.start(port, process.env.HOST || '127.0.0.1');
  console.log(`Aegis local security lab is listening at ${address.url}`);
  console.log('The API, live events, and contained lab workloads share this address.');
} catch (error) {
  console.error(`Cannot start Aegis: ${error.message}`);
  await platform.stop();
  process.exitCode = 1;
}

let shuttingDown = false;
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, async () => {
    if (shuttingDown) return;
    shuttingDown = true;
    await platform.stop();
    process.exit(0);
  });
}
