import fs from 'node:fs';

const [beforeFile, afterFile] = process.argv.slice(2);
if (!beforeFile || !afterFile) {
  throw new Error('Usage: npm run heldout:compare -- results/before.json results/after.json');
}

const before = JSON.parse(fs.readFileSync(beforeFile, 'utf8'));
const after = JSON.parse(fs.readFileSync(afterFile, 'utf8'));
for (const [name, report] of [['before', before], ['after', after]]) {
  if (report.suite !== 'HELD-OUT RED TEAM' || !report.metrics) {
    throw new Error(`${name} must be a saved held-out benchmark result`);
  }
}
if (before.seed !== after.seed || before.metrics.attacks !== after.metrics.attacks
  || before.metrics.legitimate !== after.metrics.legitimate) {
  throw new Error('Before and after reports must use the same seed and sample counts');
}

console.log(JSON.stringify({
  before: { file: beforeFile, seed: before.seed, metrics: before.metrics, criticalBypasses: before.criticalBypasses.length },
  after: { file: afterFile, seed: after.seed, metrics: after.metrics, criticalBypasses: after.criticalBypasses.length },
  changePercentagePoints: {
    attackContainment: Math.round((after.metrics.attackContainmentRate - before.metrics.attackContainmentRate) * 100) / 100,
    legitimatePass: Math.round((after.metrics.legitimatePassRate - before.metrics.legitimatePassRate) * 100) / 100
  }
}, null, 2));
