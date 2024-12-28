const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Controller สำหรับ Register
exports.register = async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // ตรวจสอบว่ามีผู้ใช้อยู่แล้วหรือไม่
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ msg: 'ผู้ใช้นี้มีอยู่ในระบบแล้ว' });
    }

    // สร้างผู้ใช้ใหม่
    user = new User({
      username,
      email,
      password
    });

    // เข้ารหัสรหัสผ่าน
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password, salt);

    await user.save();

    // สร้าง JWT token
    const payload = {
      user: {
        id: user.id
      }
    };

    jwt.sign(
      payload,
      process.env.JWT_SECRET,
      { expiresIn: '1h' },
      (err, token) => {
        if (err) throw err;
        res.json({ 
          success: true,
          token,
          user: {
            id: user.id,
            username: user.username,
            email: user.email
          }
        });
      }
    );
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ 
      success: false,
      msg: 'เกิดข้อผิดพลาดที่เซิร์ฟเวอร์' 
    });
  }
};

// Controller สำหรับ Login
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // ตรวจสอบว่ามีผู้ใช้อยู่หรือไม่
    let user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ 
        success: false,
        msg: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง' 
      });
    }

    // ตรวจสอบรหัสผ่าน
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ 
        success: false,
        msg: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง' 
      });
    }

    // สร้าง JWT token
    const payload = {
      user: {
        id: user.id
      }
    };

    jwt.sign(
      payload,
      process.env.JWT_SECRET,
      { expiresIn: '1h' },
      (err, token) => {
        if (err) throw err;
        res.json({
          success: true,
          token,
          user: {
            id: user.id,
            username: user.username,
            email: user.email
          }
        });
      }
    );
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ 
      success: false,
      msg: 'เกิดข้อผิดพลาดที่เซิร์ฟเวอร์' 
    });
  }
};

// Controller สำหรับดึงข้อมูลผู้ใช้
exports.getMe = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.json({
      success: true,
      user
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ 
      success: false,
      msg: 'เกิดข้อผิดพลาดที่เซิร์ฟเวอร์' 
    });
  }
}; 