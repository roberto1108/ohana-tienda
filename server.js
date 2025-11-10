// --- Dependencias principales ---
import express from "express";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import multer from "multer";
import path from "path";
import fs from "fs";
import nodemailer from "nodemailer";
import twilio from "twilio";
import dotenv from "dotenv";
import { fileURLToPath } from "url";

dotenv.config(); // carga las variables de entorno

// --- Configuración de rutas absolutas ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// --- Middleware global ---
app.use(cors({ origin: "*", methods: ["GET", "POST", "PUT", "DELETE"] }));
app.use(express.json({ limit: "10mb" }));
app.use("/uploads", express.static(path.join(process.cwd(), "uploads")));

// --- Configuración de constantes ---
const JWT_SECRET = process.env.JWT_SECRET || "cambialo_por_una_clave_segura";
const PORT = process.env.PORT || 10000;

// --- Inicialización de base de datos ---
let db;
(async () => {
  db = await open({
    filename: "./db.sqlite",
    driver: sqlite3.Database,
  });

  // Crear tablas
  await db.exec(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT
    );

    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      price REAL,
      stock INTEGER,
      code TEXT,
      proveedor TEXT
    );

    CREATE TABLE IF NOT EXISTS sales (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      created_at TEXT,
      total REAL,
      items TEXT
    );

    CREATE TABLE IF NOT EXISTS debtors (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      phone TEXT,
      description TEXT,
      items TEXT,
      total REAL,
      created_at TEXT,
      paid INTEGER DEFAULT 0
    );
  `);

  // Crear usuario admin si no existe
  const admin = await db.get("SELECT * FROM usuarios WHERE username = ?", ["admin"]);
  if (!admin) {
    const hash = await bcrypt.hash("admin123", 10);
    await db.run("INSERT INTO usuarios (username, password) VALUES (?, ?)", [
      "admin",
      hash,
    ]);
    console.log("✅ Usuario 'admin' creado con contraseña 'admin123'");
  } else {
    console.log("🟢 Usuario 'admin' ya existe");
  }
})();

// --- Middleware de autenticación ---
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: "No autorizado" });
  const token = auth.split(" ")[1];
  try {
    const data = jwt.verify(token, JWT_SECRET);
    req.user = data;
    next();
  } catch {
    return res.status(401).json({ error: "Token inválido" });
  }
}

// ============================
//         ENDPOINTS
// ============================

// --- LOGIN ---
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await db.get("SELECT * FROM usuarios WHERE username = ?", [username]);
    if (!user) return res.status(401).json({ error: "Credenciales inválidas" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: "Credenciales inválidas" });

    const token = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: "8h" }
    );
    res.json({ token, user: { id: user.id, username: user.username } });
  } catch (err) {
    console.error("Error en login:", err);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

// --- PRODUCTOS ---
app.get("/api/products", authMiddleware, async (req, res) => {
  const rows = await db.all("SELECT * FROM products ORDER BY id DESC");
  res.json(rows);
});

app.post("/api/products", authMiddleware, async (req, res) => {
  const { name, price, stock, code, proveedor } = req.body;
  if (!name || !price || !stock || !code || !proveedor)
    return res.status(400).json({ error: "Datos incompletos" });

  const result = await db.run(
    "INSERT INTO products (name, price, stock, code, proveedor) VALUES (?, ?, ?, ?, ?)",
    [name, price, stock, code, proveedor]
  );
  const prod = await db.get("SELECT * FROM products WHERE id = ?", result.lastID);
  res.json(prod);
});

app.put("/api/products/:id", authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { name, price, stock, code, proveedor } = req.body;
  await db.run(
    "UPDATE products SET name=?, price=?, stock=?, code=?, proveedor=? WHERE id=?",
    [name, price, stock, code, proveedor, id]
  );
  const prod = await db.get("SELECT * FROM products WHERE id = ?", id);
  res.json(prod);
});

app.delete("/api/products/:id", authMiddleware, async (req, res) => {
  const { id } = req.params;
  await db.run("DELETE FROM products WHERE id = ?", id);
  res.json({ ok: true });
});

// --- VENTAS ---
app.post("/api/sales", authMiddleware, async (req, res) => {
  const { items, total } = req.body;
  const created_at = new Date().toISOString();
  await db.run("INSERT INTO sales (created_at, total, items) VALUES (?, ?, ?)", [
    created_at,
    total,
    JSON.stringify(items),
  ]);
  for (const it of items) {
    await db.run("UPDATE products SET stock = stock - ? WHERE id = ?", [
      it.qty,
      it.productId,
    ]);
  }
  res.json({ ok: true });
});

app.get("/api/sales", authMiddleware, async (req, res) => {
  const rows = await db.all("SELECT * FROM sales ORDER BY id DESC");
  res.json(rows);
});

// --- DEUDORES ---
app.get("/api/debtors", authMiddleware, async (req, res) => {
  const rows = await db.all("SELECT * FROM debtors ORDER BY id DESC");
  res.json(rows.map((d) => ({ ...d, items: d.items ? JSON.parse(d.items) : [] })));
});

app.post("/api/debtors", authMiddleware, async (req, res) => {
  try {
    const { name, phone, description, items, total } = req.body;
    if (!name || !items || items.length === 0 || !total)
      return res.status(400).json({ error: "Faltan datos requeridos" });

    const created_at = new Date().toISOString();
    const result = await db.run(
      "INSERT INTO debtors (name, phone, description, items, total, created_at, paid) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [name, phone || "", description || "", JSON.stringify(items), total, created_at, 0]
    );
    const debtor = await db.get("SELECT * FROM debtors WHERE id = ?", result.lastID);
    res.json({ ...debtor, items });
  } catch (err) {
    console.error("💥 Error al guardar deudor:", err);
    res.status(500).json({ error: "Error al guardar deudor" });
  }
});

app.put("/api/debtors/:id", authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { name, phone, description, items, total, paid } = req.body;

  await db.run(
    "UPDATE debtors SET name=?, phone=?, description=?, items=?, total=?, paid=? WHERE id=?",
    [name, phone, description, JSON.stringify(items || []), total, paid ? 1 : 0, id]
  );

  const updated = await db.get("SELECT * FROM debtors WHERE id = ?", id);
  res.json({ ...updated, items: updated.items ? JSON.parse(updated.items) : [] });
});

app.delete("/api/debtors/:id", authMiddleware, async (req, res) => {
  const { id } = req.params;
  await db.run("DELETE FROM debtors WHERE id = ?", id);
  res.json({ ok: true });
});

// --- ENVIAR TICKET POR CORREO ---
app.post("/api/send-ticket", authMiddleware, async (req, res) => {
  const { email, cart, total } = req.body;
  if (!email || !cart || cart.length === 0)
    return res.status(400).json({ error: "Datos incompletos" });

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
  });

  const itemsHtml = cart
    .map((item) => `<li>${item.qty} × ${item.name} — $${item.price * item.qty}</li>`)
    .join("");
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Tu ticket de compra",
    html: `<h2>Gracias por tu compra</h2><ul>${itemsHtml}</ul><p><b>Total:</b> $${total}</p>`,
  };

  try {
    await transporter.sendMail(mailOptions);
    res.json({ ok: true, message: "Ticket enviado" });
  } catch (err) {
    console.error("Error enviando ticket:", err);
    res.status(500).json({ error: "Error al enviar el ticket" });
  }
});

// --- ENVIAR TICKET POR SMS ---
const twilioClient = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN);

app.post("/api/send-sms", authMiddleware, async (req, res) => {
  const { phone, cart, total } = req.body;
  if (!phone || !cart || cart.length === 0)
    return res.status(400).json({ error: "Datos incompletos" });

  const itemsText = cart
    .map((item) => `${item.qty}×${item.name}=$${item.price * item.qty}`)
    .join(", ");
  try {
    await twilioClient.messages.create({
      body: `Gracias por tu compra. Items: ${itemsText}. Total: $${total}`,
      from: process.env.SMS_FROM,
      to: phone,
    });
    res.json({ ok: true, message: "SMS enviado" });
  } catch (err) {
    console.error("Error enviando SMS:", err);
    res.status(500).json({ error: "Error al enviar SMS" });
  }
});

// --- SUBIR LOGO ---
const upload = multer({ dest: "uploads/" });
app.post("/api/upload-logo", authMiddleware, upload.single("logo"), (req, res) => {
  const tempPath = req.file.path;
  const targetPath = path.join(
    process.cwd(),
    "uploads",
    "logo" + path.extname(req.file.originalname)
  );
  fs.renameSync(tempPath, targetPath);
  res.json({ url: `/uploads/${path.basename(targetPath)}` });
});

// --- Servir frontend React (Render) ---
const frontendPath = path.join(__dirname, "public");
if (fs.existsSync(frontendPath)) {
  app.use(express.static(frontendPath));
  app.get("*", (req, res) => {
    res.sendFile(path.join(frontendPath, "index.html"));
  });
}

// --- Iniciar servidor ---
app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ Servidor corriendo en el puerto ${PORT}`);
});
