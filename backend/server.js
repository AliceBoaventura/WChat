const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data', 'envelopes.json');

app.use(cors());
app.use(express.json());

function readData(){
  const raw = fs.readFileSync(DATA_FILE, 'utf8');
  return JSON.parse(raw);
}
function writeData(data){
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), 'utf8');
}

app.get('/api/envelopes', (req, res) => {
  const data = readData();
  res.json({ items: data.envelopes });
});

app.post('/api/open/:id', (req, res) => {
  const id = parseInt(req.params.id, 10);
  const data = readData();
  const env = data.envelopes.find(e => e.id === id);
  if(!env) return res.status(404).json({ error: 'not found' });
  if(env.opened) return res.status(400).json({ error: 'already opened' });
  env.opened = true;
  // reveal a random amount if not already set
  if (!env.cents || env.cents === 0) {
    env.cents = Math.floor(Math.random() * 10000) + 100; // 1.00 - 101.00 BRL (cents)
  }
  writeData(data);
  res.json(env);
});

app.post('/api/reveal/:id', (req, res) => {
  const id = parseInt(req.params.id, 10);
  const data = readData();
  const env = data.envelopes.find(e => e.id === id);
  if(!env) return res.status(404).json({ error: 'not found' });
  env.revealed = true;
  writeData(data);
  res.json(env);
});

app.listen(PORT, () => {
  console.log(`Lucky Money API running on port ${PORT}`);
});
