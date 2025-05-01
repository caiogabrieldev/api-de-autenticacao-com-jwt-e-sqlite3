const express=require('express')
const bcrypt = require('bcryptjs');
require('dotenv').config()
const jwt = require('jsonwebtoken');
const cors=require('cors')
const app=express()

app.use(express.json())
app.use(cors())

const JWT_SECRET = process.env.JWT_SECRET
const PORT=4090

const {Sequelize, DataTypes, where}=require("sequelize")
const conexaoComDB=new Sequelize({
    dialect:'sqlite',
    storage:'users.sqlite'
})

const users=conexaoComDB.define('Usuarios', {
    id:{
        type:DataTypes.INTEGER,
        autoIncrement: true,
        primaryKey: true,
        allowNull: false,
        unique: true,
    },
    email:{
        type: DataTypes.STRING(50),
        allowNull: false,
        unique: true
    },
    senha: {
        type: DataTypes.STRING(50),
        allowNull: false
    }
})
async function sincronizarDB(){
    try {
        await conexaoComDB.sync()
    } catch (error) {
        console.log("Erro ao sincronizar")
    }
}
sincronizarDB()

app.listen(PORT, ()=>{
    console.log(`Servidor rodando em: http://localhost:${PORT}`);
})

app.use('/registrar', async (req,res)=>{
    const {email, senha}=req.body
    const existe= await users.findAll({where: {email:email}})
  
    if(existe.length!=0){
        return res.status(400).json({message: 'O usuário já existe'})
    }

    const hashed= await bcrypt.hash(senha, 8)
    const user={
        email:email,
        senha:hashed
    }
    await users.create(user)
    await res.status(200).json({message: "Usuário criado com sucesso!"})
})

app.post('/login', async (req,res)=>{
    const {email,senha}=req.body

    const user=await users.findAll({where:{email:email}})
    
    if(!user.length===0){
        return res.status(404).json({message: "Email não cadastrado"})
    }
    const compararSenha=await bcrypt.compare(senha, user[0].senha)
    if(!compararSenha){
        return res.status(400).json({message: "Credenciais inválidas"})
    }
    const token=jwt.sign({id:user[0].id}, JWT_SECRET,{expiresIn:"1h"})
    return res.status(200).json({token})

})

function authMiddeleware(req,res,next) {
    const authHeader=req.headers.authorization
    if(!authHeader){
        return res.status(400).json({error: 'Token ausente'})

    }
    const token=authHeader.split(' ')[1]
    try {
        const decoded=jwt.verify(token, JWT_SECRET)
        req.id=decoded.id
        next()
    } catch (error) {
        return res.status(400).json({message: "Token inválido"})
    }
}
app.get('/rotaprivada',authMiddeleware,async (req,res)=>{
    const user=await users.findAll({where:{id:req.id}})
    res.status(200).json({message: `Olá ${user[0].email}, bem vindo!`})
})