const jwt = require('jsonwebtoken');

module.exports = function(req, res, next) {
  // ดึง token จาก header
  const token = req.header('x-auth-token');

  // ตรวจสอบว่ามี token หรือไม่
  if (!token) {
    return res.status(401).json({ 
      success: false,
      msg: 'ไม่พบ token, การเข้าถึงถูกปฏิเสธ' 
    });
  }

  try {
    // ตรวจสอบ token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // เพิ่มข้อมูล user ใน request
    req.user = decoded.user;
    next();
  } catch (err) {
    res.status(401).json({ 
      success: false,
      msg: 'Token ไม่ถูกต้อง' 
    });
  }
}; 