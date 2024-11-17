// app.js

require("dotenv").config();
const express = require("express");
const session = require("express-session");
const flash = require("connect-flash");
const csrf = require("csurf");
const helmet = require("helmet");
const path = require("path");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const sqlite3 = require("sqlite3").verbose();
const { body, validationResult } = require("express-validator");

const app = express();

// Set View Engine ke EJS
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Middleware Keamanan dengan Helmet
app.use(helmet());

// Middleware Statis untuk Folder Public
app.use(express.static(path.join(__dirname, "public")));

// Middleware untuk Parsing URL-Encoded Data dan JSON
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Konfigurasi Sesi
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true },
  })
);

// Flash Messages
app.use(flash());

// CSRF Protection
app.use(csrf());

// Middleware untuk Mengoper Data ke Views
app.use((req, res, next) => {
  try {
    res.locals.csrfToken = req.csrfToken();
  } catch (err) {
    if (err.code === "EBADCSRFTOKEN") {
      // Handle CSRF token errors here
      res.status(403).send("Form tampered with.");
      return;
    }
    return next(err);
  }
  res.locals.isAuthenticated = req.session.userId ? true : false;
  res.locals.flash = req.flash();
  res.locals.session = req.session; // Penting: Menyimpan sesi ke res.locals
  next();
});

// Konfigurasi Multer untuk Upload File
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "public/uploads/");
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  },
});

// Filter untuk Jenis File yang Diizinkan
const fileFilter = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png|gif/;
  const extname = allowedTypes.test(
    path.extname(file.originalname).toLowerCase()
  );
  const mimetype = allowedTypes.test(file.mimetype);
  if (mimetype && extname) {
    return cb(null, true);
  } else {
    cb(new Error("Error: Hanya menerima file gambar (jpeg, jpg, png, gif)!"));
  }
};

// Inisialisasi Multer
const upload = multer({
  storage: storage,
  limits: { fileSize: 1024 * 1024 }, // Maksimum 1MB
  fileFilter: fileFilter,
});

// Koneksi ke Database SQLite
const db = new sqlite3.Database(
  path.join(__dirname, "database.sqlite"),
  (err) => {
    if (err) {
      console.error(err.message);
    }
    console.log("Terhubung ke database SQLite.");
  }
);

// Inisialisasi Database dan Data Awal
db.serialize(() => {
  // Tabel Users
  db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL
    )`);

  // Tabel Students
  db.run(`CREATE TABLE IF NOT EXISTS students (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        phone TEXT,
        address TEXT,
        photo TEXT
    )`);

  // Insert Admin jika belum ada
  db.get("SELECT * FROM users WHERE username = ?", ["admin"], (err, row) => {
    if (err) {
      console.error(err.message);
    }
    if (!row) {
      const hashedPassword = bcrypt.hashSync("admin123", 10);
      db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", [
        "admin",
        hashedPassword,
        "dosen",
      ]);
      console.log(
        "Admin default ditambahkan: username: admin, password: admin123"
      );
    }
  });

  // Insert Mahasiswa jika belum ada
  db.get("SELECT * FROM users WHERE username = ?", ["student"], (err, row) => {
    if (err) {
      console.error(err.message);
    }
    if (!row) {
      const hashedPassword = bcrypt.hashSync("student123", 10);
      db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", [
        "student",
        hashedPassword,
        "mahasiswa",
      ]);
      console.log(
        "Mahasiswa default ditambahkan: username: student, password: student123"
      );
    }
  });
});

// Middleware untuk Memeriksa Autentikasi
function isAuthenticated(req, res, next) {
  if (req.session.userId) {
    next();
  } else {
    res.redirect("/login");
  }
}

// Middleware untuk Memeriksa Peran Dosen
function isDosen(req, res, next) {
  if (req.session.role === "dosen") {
    next();
  } else {
    res.status(403).send("Forbidden");
  }
}

// Routes

// GET /login
app.get("/login", (req, res) => {
  res.render("login");
});

// POST /login
app.post(
  "/login",
  [
    body("username").trim().notEmpty().withMessage("Username wajib diisi"),
    body("password").notEmpty().withMessage("Password wajib diisi"),
    body("captcha").notEmpty().withMessage("Captcha wajib diisi"),
  ],
  (req, res) => {
    const errors = validationResult(req);
    const { username, password, captcha } = req.body;

    // Validasi CAPTCHA di Backend
    if (captcha !== "7") {
      // Karena CAPTCHA sederhana: 3 + 4 = 7
      req.flash("error", "Captcha salah");
      return res.redirect("/login");
    }

    if (!errors.isEmpty()) {
      req.flash(
        "error",
        errors.array().map((err) => err.msg)
      );
      return res.redirect("/login");
    }

    db.get(
      "SELECT * FROM users WHERE username = ?",
      [username],
      (err, user) => {
        if (err) {
          req.flash("error", "Kesalahan database");
          return res.redirect("/login");
        }
        if (!user) {
          req.flash("error", "Username atau password salah");
          return res.redirect("/login");
        }

        if (bcrypt.compareSync(password, user.password)) {
          req.session.userId = user.id;
          req.session.role = user.role;
          req.session.username = user.username;
          res.redirect("/dashboard");
        } else {
          req.flash("error", "Username atau password salah");
          res.redirect("/login");
        }
      }
    );
  }
);

// GET /logout
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/login");
});

// GET /dashboard
app.get("/dashboard", isAuthenticated, (req, res) => {
  if (req.session.role === "dosen") {
    db.all("SELECT * FROM students", [], (err, students) => {
      if (err) {
        req.flash("error", "Kesalahan database");
        return res.redirect("/login");
      }
      res.render("dashboard", { students });
    });
  } else {
    db.get(
      "SELECT * FROM students WHERE email = ?",
      [req.session.username],
      (err, student) => {
        if (err) {
          req.flash("error", "Kesalahan database");
          return res.redirect("/login");
        }
        res.render("dashboard", { student });
      }
    );
  }
});

// GET /add
app.get("/add", isAuthenticated, isDosen, (req, res) => {
  res.render("add");
});

// POST /add
app.post(
  "/add",
  isAuthenticated,
  isDosen,
  upload.single("photo"),
  [
    body("name").trim().notEmpty().withMessage("Nama wajib diisi"),
    body("email").isEmail().withMessage("Email valid wajib diisi"),
    body("phone").trim().optional(),
    body("address").trim().optional(),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      req.flash(
        "error",
        errors.array().map((err) => err.msg)
      );
      return res.redirect("/add");
    }

    const { name, email, phone, address } = req.body;
    const photo = req.file ? req.file.filename : null;

    db.run(
      "INSERT INTO students (name, email, phone, address, photo) VALUES (?, ?, ?, ?, ?)",
      [name, email, phone, address, photo],
      function (err) {
        if (err) {
          req.flash("error", "Kesalahan database atau email sudah terdaftar");
          return res.redirect("/add");
        }
        req.flash("success", "Mahasiswa berhasil ditambahkan");
        res.redirect("/dashboard");
      }
    );
  }
);

// GET /edit/:id
app.get("/edit/:id", isAuthenticated, (req, res) => {
  const id = req.params.id;

  if (req.session.role === "mahasiswa") {
    db.get(
      "SELECT * FROM students WHERE id = ? AND email = ?",
      [id, req.session.username],
      (err, student) => {
        if (err || !student) {
          req.flash("error", "Mahasiswa tidak ditemukan");
          return res.redirect("/dashboard");
        }
        res.render("edit", { student });
      }
    );
  } else if (req.session.role === "dosen") {
    db.get("SELECT * FROM students WHERE id = ?", [id], (err, student) => {
      if (err || !student) {
        req.flash("error", "Mahasiswa tidak ditemukan");
        return res.redirect("/dashboard");
      }
      res.render("edit", { student });
    });
  } else {
    res.status(403).send("Forbidden");
  }
});

// POST /edit/:id
app.post(
  "/edit/:id",
  isAuthenticated,
  upload.single("photo"),
  [
    body("name").trim().notEmpty().withMessage("Nama wajib diisi"),
    body("email").isEmail().withMessage("Email valid wajib diisi"),
    body("phone").trim().optional(),
    body("address").trim().optional(),
  ],
  (req, res) => {
    const id = req.params.id;
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      req.flash(
        "error",
        errors.array().map((err) => err.msg)
      );
      return res.redirect(`/edit/${id}`);
    }

    const { name, email, phone, address } = req.body;
    const photo = req.file ? req.file.filename : null;

    if (req.session.role === "mahasiswa") {
      db.run(
        "UPDATE students SET name = ?, email = ?, phone = ?, address = ? " +
          (photo ? ", photo = ?" : "") +
          " WHERE id = ? AND email = ?",
        photo
          ? [name, email, phone, address, photo, id, req.session.username]
          : [name, email, phone, address, id, req.session.username],
        function (err) {
          if (err) {
            req.flash("error", "Kesalahan database atau email sudah terdaftar");
            return res.redirect(`/edit/${id}`);
          }
          req.flash("success", "Profil berhasil diperbarui");
          res.redirect("/dashboard");
        }
      );
    } else if (req.session.role === "dosen") {
      db.run(
        "UPDATE students SET name = ?, email = ?, phone = ?, address = ? " +
          (photo ? ", photo = ?" : "") +
          " WHERE id = ?",
        photo
          ? [name, email, phone, address, photo, id]
          : [name, email, phone, address, id],
        function (err) {
          if (err) {
            req.flash("error", "Kesalahan database atau email sudah terdaftar");
            return res.redirect(`/edit/${id}`);
          }
          req.flash("success", "Mahasiswa berhasil diperbarui");
          res.redirect("/dashboard");
        }
      );
    } else {
      res.status(403).send("Forbidden");
    }
  }
);

// POST /delete/:id
app.post("/delete/:id", isAuthenticated, isDosen, (req, res) => {
  const id = req.params.id;
  db.run("DELETE FROM students WHERE id = ?", [id], function (err) {
    if (err) {
      req.flash("error", "Kesalahan database");
      return res.redirect("/dashboard");
    }
    req.flash("success", "Mahasiswa berhasil dihapus");
    res.redirect("/dashboard");
  });
});

// Redirect Root ke /login
app.get("/", (req, res) => {
  res.redirect("/login");
});

// Mulai Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server berjalan di port ${PORT}`);
});
