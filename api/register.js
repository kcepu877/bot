import { hash } from 'bcryptjs';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  const { email, password } = req.body;
  const hashed = await hash(password, 10);

  // Simpan ke database (Cloudflare D1 atau lainnya)
  // Contoh pseudo:
  // await db.prepare("INSERT INTO users ...").run(...)

  res.status(200).json({ message: 'Registered' });
}
