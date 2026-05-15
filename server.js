const express = require('express');
const db = require('./conn');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express()
const port = 3000
const SECRET_KEY = "123456789"
//middle ware
app.use(express.json())
function autheticateToken(req,res,next) {
    if (!req.headers.authorization) {
        res.status(401).send({error:"authorization header is required"});
        return;
    }
    const token = req.headers.authorization.split(' ')[1];
    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).send({error:"invalid token"});
    }
}

//new student
app.post('/api/new/student',autheticateToken, async (req,res)=>{
    const { full_name, level } = req.body; 

    if(!full_name || !level){
        res.status(400).send({error:"all fields are required"});
        return;
    }
    try {
        const sql = "INSERT INTO students(full_name, class) VALUES(?,?)";
        const [result] = await db.query(sql, [full_name, level]);
        res.status(201).send({message: "Student added successfully", id: result.insertId});
    } catch(err) {
        res.status(500).send({error: err.message});
    }
})
app.post('/api/new/librarians',autheticateToken, async (req,res)=>{
    const { full_name, phone_number ,password} = req.body; 

    if(!full_name || !phone_number || !password){
        res.status(400).send({error:"all fields are required"});
        return;
    }
    try {
        //checking if the phone number already exists
        const [existing] = await db.query("SELECT id FROM librarians WHERE phone_number = ?", [phone_number]);
        if(existing.length > 0){
            res.status(400).send({error:"phone number already exists"});
            return;
        }   
        const sql = "INSERT INTO librarians(full_name, phone_number, password) VALUES(?,?,?)";
        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await db.query(sql, [full_name, phone_number, hashedPassword]);
        res.status(201).send({message: "Librarian added successfully", id: result.insertId});
    } catch(err) {
        res.status(500).send({error: err.message});
    }
})
app.post('/api/new/borrowed_book',autheticateToken, async (req,res)=>{
    const { student_id, book_id,librarian_id,borrowed_date,return_date } = req.body; 

    if(!student_id || !book_id || !librarian_id || !borrowed_date || !return_date){
        res.status(400).send({error:"all fields are required"});
        return;
    }
    try {
        const sql = "INSERT INTO borrowed_books(student_id, book_id,librarian_id,borrowed_date,return_date) VALUES(?,?,?,?,?)";
        const [result] = await db.query(sql, [student_id, book_id, librarian_id, borrowed_date, return_date]);
        res.status(201).send({message: "Borrowed book added successfully", id: result.insertId});
    } catch(err) {
        res.status(500).send({error: err.message});
    }
})

app.post('/api/new/books',autheticateToken, async (req,res)=>{
    const { title, category,author_name } = req.body; 

    if(!title || !category || !author_name){
        res.status(400).send({error:"all fields are required"});
        return;
    }
    try {
        const sql = "INSERT INTO books(title, category, author_name) VALUES(?,?,?)";
        const [result] = await db.query(sql, [title, category, author_name]);
        res.status(201).send({message: "Book added successfully", id: result.insertId});
    } catch(err) {
        res.status(500).send({error: err.message});
    }
})  

app.post('/api/librarians/login', async (req,res)=>{
    const { phone_number, password } = req.body;
    if (!phone_number || !password) {
        res.status(400).send({error:"phone number and password are required"});
        return;
    }
    try {
        const [librarian] = await db.query("SELECT * FROM librarians WHERE phone_number = ?", [phone_number]);
        if (librarian.length === 0) {
            res.status(404).send({error:"librarian not found"});
            return;
        }
        const isMatch = await bcrypt.compare(password, librarian[0].password);
        if (!isMatch) {
            res.status(401).send({error:"invalid password"});
            return;
        }

        const payload = { 
            id: librarian[0].id,
            name:librarian[0].full_name
         };

         const token = jwt.sign(payload,SECRET_KEY, {expiresIn: '1h'});

        res.status(200).send({message: "librarian logged in successfully", token});
    } catch (err) {
        res.status(500).send({error: err.message});
    }
});
app.post('/api/book/status/:book_id', autheticateToken, async (req,res)=>{
    const { book_id } = req.params;
    const {status} = req.body
    if (!book_id) {
        return res.status(404).send({error:"book id is required"});
    }
    //checking if the book exists
    const sql = "SELECT id FROM books WHERE id = ?";
    const [result] = await db.query(sql, [book_id]);
    if (result.length === 0) {
        return res.status(404).send({error:"book not found"});
    }
    //updating the book status
    const updateSql = "UPDATE borrowed_books SET status = ? WHERE id = ?";
    const [updateResult] = await db.query(updateSql, [status, book_id]);
    res.status(200).send({message: "book status updated successfully"});

})


app.listen(port,()=>{
    console.log(`express server running on http://localhost:${port}`);
})