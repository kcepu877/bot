import { compare } from 'bcryptjs';
import jwt from 'jsonwebtoken';

export default async function handler(req, res) {
  const { email, password } = req.body;

  // Ambil user dari DB
  const user = {}; // pseudo: await db.get("SELECT * FROM users WHERE email = ?", [email])

  const match = await compare(password, user.password);
  if (!match) return res.status(401).json({ message: 'Invalid' });

  const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.status(200).json({ token });
}
