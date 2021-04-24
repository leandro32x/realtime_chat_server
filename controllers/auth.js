const { response } = require("express");
const bcrypt = require('bcryptjs');

const { validationResult } = require("express-validator");
const Usuario = require("../models/usuario");
const {generarJWT} = require('../helpers/jwt');

const crearUsuario = async (req, res = response)=>{

    const { email, password } = req.body;
    
    try{
        
        const existeEmail = await Usuario.findOne({email});
        if(existeEmail){
            return res.status(400).json({
                ok: false,
                msg: "Este correo electronico ya esta registrado"
            })
        }
        
        const usuario = new Usuario(req.body);

        //Encriptar contraseña
        const salt = bcrypt.genSaltSync();
        usuario.password = bcrypt.hashSync( password, salt);

        
        await usuario.save();
        
        // Genera JWT
        const token = await generarJWT(usuario.id);

        res.json({
            ok: true,
            usuario,
            token
        });
    }catch(error){
        console.log(error);
        res.status(500).json({
            ok: false,
            msg: 'Hable con el administrador'
        });
    }


}

const login = async (req, res = response)=>{

    const {email, password } = req.body;

    try{
        const usuarioDB = await Usuario.findOne({email});
        if(!usuarioDB){
            return res.status(404).json({
                ok: false,
                msg: "Usuario o contraseña invalido"
            });
        }

        const validPassword = bcrypt.compareSync(password, usuarioDB.password);
        if(!validPassword){
            return res.status(404).json({
                ok: false,
                msg: "Usuario o contraseña invalido"
            });
        }
        //generarJWT
        const token = await generarJWT(usuarioDB.id);

        res.json({
            ok: true,
            usuario: usuarioDB,
            token
        });

    }catch(error){
        console.log(error)
        return res.json({
            ok: false,
            msg: 'Hable con el administrador'
        });
    }
}

const renewToken = async (req, res = response)=>{
    const { uid } = req.body;

    if(!uid){
        return res.status(400).json({
            ok: false,
            msg: "Missing parameter uid"
        })
    }

    const usuarioDB = await Usuario.findById(uid);
    if(!usuarioDB){
        return res.status(400).json({
            ok: false,
            msg: "Usuario o contraseña invalido"
        });
    }
    //generarJWT
    const token = await generarJWT(usuarioDB.id);

    return res.json({
        ok: true,
        usuarioDB,
        token
    })
}

module.exports={
    crearUsuario,
    login,
    renewToken
}