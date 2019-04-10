/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * Autores: Marcos Vázquez Fernández y Lara Souto Alonso
 * Grupo: SSI_1
 * 
 */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class EmpaquetarExamen {

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, FileNotFoundException, IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, SignatureException {
        
        // Comprobar argumentos
	if (args.length != 4) {
            
            mensajeAyuda();
            System.exit(1);
	}
        
        String pathExamen = args[0];
        String pathPaquete = args[1];
        String clavePublicaProfesor = args[2];
        String clavePrivadaAlumno = args[3];
        
        
        /* Cargar "provider" BC */
	Security.addProvider(new BouncyCastleProvider());
        
        /*** PASO 1: Crear e inicializar clave ***/
        System.out.println("\n-------------------------------");
        System.out.println("1. Generar clave DES");
        System.out.println("\n-------------------------------");
        KeyGenerator generadorClaveDES = KeyGenerator.getInstance("DES", "BC");
        generadorClaveDES.init(56); // clave de 56 bits
        SecretKey clave = generadorClaveDES.generateKey();
        
        /*** PASO 2: Crear cifrador ***/
	Cipher cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding", "BC");
	// Algoritmo DES
	// Modo : ECB (Electronic Code Book)
	// Relleno : PKCS5Padding
	// 
        
        /*****************************************************************/
	System.out.println("2. Cifrar con DES el fichero " + pathExamen);
        
        /*** PASO 2a: Inicializar cifrador en modo CIFRADO ***/
	cifrador.init(Cipher.ENCRYPT_MODE, clave);
        
        /* Leer fichero y pasarlo al cifrador */
	File ficheroExamen = new File(pathExamen); 
	int tamanoFicheroExamen = (int) ficheroExamen.length();
	byte[] bufferExamen = new byte[tamanoFicheroExamen];
	FileInputStream in = new FileInputStream(ficheroExamen);
	in.read(bufferExamen, 0, tamanoFicheroExamen);
	
        byte[] bufferExamenCifrado;
	
        bufferExamenCifrado = cifrador.doFinal(bufferExamen); // Completar cifrado (procesa relleno, puede devolver texto)
        System.out.println("EXAMEN CIFRADO");
        System.out.println("\n-------------------------------");
	
        
        Paquete p = new Paquete();
        p.anadirBloque("examen cifrado", bufferExamenCifrado);// Escribir final del texto cifrado (si lo hay) 
		
	in.close();
        
        /***Paso 3: Recuperar clave PUBLICA del fichero ***/
	
        /*** Crear KeyFactory (depende del provider) usado para las transformaciones de claves*/
	KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC"); // Hace uso del provider BC
        
        // 3.1 Leer datos binarios x809
	File ficheroClavePublica = new File(clavePublicaProfesor); 
	int tamanoFicheroClavePublica = (int) ficheroClavePublica.length();
	byte[] bufferPub = new byte[tamanoFicheroClavePublica];
	in = new FileInputStream(ficheroClavePublica);
	in.read(bufferPub, 0, tamanoFicheroClavePublica);
	in.close();

	// 3.2 Recuperar clave publica desde datos codificados en formato X509
	X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(bufferPub);
	PublicKey clavePublica = keyFactoryRSA.generatePublic(clavePublicaSpec);
        System.out.println("3. Clave publica profesor recuperada");
        System.out.println("\n-------------------------------");
        
        /*** Paso 4: Cifrar clave secreta con clave pública del profesor recuperada del fichero ***/
        
        // PASO 4.1: Crear cifrador RSA
        Cipher cifradorRSA = Cipher.getInstance("RSA", "BC"); // Hace uso del provider BC

        // PASO 4.2: Poner cifrador en modo CIFRADO 
        cifradorRSA.init(Cipher.ENCRYPT_MODE, clavePublica);  // Cifra con la clave publica

        System.out.println("4. Cifrar con clave publica la clave secreta");
        byte[] bufferCifrado = cifradorRSA.doFinal(clave.getEncoded());
        System.out.println("CLAVE SECRETA CIFRADA");
        System.out.println("\n-------------------------------");
        
        p.anadirBloque("clave cifrada", bufferCifrado);// Escribir final del texto cifrado (si lo hay) 
        
        /*** PASO 5: Recuperar clave privada del Alumno ***/
        
	// 5.1 Leer datos binarios PKCS8
	File ficheroClavePrivada = new File(clavePrivadaAlumno); 
	int tamanoFicheroClavePrivada = (int) ficheroClavePrivada.length();
	byte[] bufferPriv = new byte[tamanoFicheroClavePrivada];
	FileInputStream inp = new FileInputStream(ficheroClavePrivada);
	inp.read(bufferPriv, 0, tamanoFicheroClavePrivada);
	inp.close();

	// 5.2 Recuperar clave privada desde datos codificados en formato PKCS8
	PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bufferPriv);
	PrivateKey clavePrivada = keyFactoryRSA.generatePrivate(clavePrivadaSpec);
	System.out.println("5.Clave privada alumno recuperada");
        System.out.println("\n-------------------------------");
        
        /*** PASO 6: Configurar objeto Signature en modo FIRMA, firmar datos y añadir la firma al paquete ***/
		
	/* Creamos la instancia del objeto signature */
        Signature firmador = Signature.getInstance("MD5withRSA", "BC");
		
	//6.1: Configuramos el objeto Signature en modo firma
	firmador.initSign(clavePrivada);
        
        //6.2: Alimentamos los datos afirmar
        firmador.update(bufferExamen);
        
        //6.3: Generar firma
        byte[] firma;
        firma = firmador.sign();
        System.out.println("6. Datos firmados y firma añadida al paquete");
        System.out.println("\n-------------------------------");
        
        //6.4: Añadir firma al paquete
        p.anadirBloque("firma", firma);
        
        /*** PASO 7: Escribir paquete con los bloques generados en disco ***/
        PaqueteDAO.escribirPaquete(pathPaquete, p);
    }
    
    public static void mensajeAyuda() {
	
        System.out.println("Aplicacion EmpaquetarExamen");
	System.out.println("\tSintaxis:   java EmpaquetarExamen nombre_fichero_con_extension nombre_paquete fichero_clave_publica_profesor fichero_clave_privada_alumno");
	System.out.println();
    }
}