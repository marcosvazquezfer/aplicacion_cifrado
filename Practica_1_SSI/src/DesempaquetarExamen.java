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

import java.security.*;
import java.security.spec.*;

import   javax.crypto.*;
import   javax.crypto.interfaces.*;
import   javax.crypto.spec.*;

import java.io.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class DesempaquetarExamen {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, FileNotFoundException, IOException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException {
        // TODO code application logic here
        
        // Comprobar argumentos
	if (args.length != 5) {
            
            mensajeAyuda();
            System.exit(1);
	}
        
        String pathPaquete = args[0];
        String pathExamenClaro = args[1];
        String clavePrivadaProfesor = args[2];
        String clavePublicaAlumno = args[3];
        String clavePublicaAutoridad = args[4];
        
        /* Cargar "provider" BC */
	Security.addProvider(new BouncyCastleProvider());
        
        /* Crear paquete y leer el que se pasa por linea de comandos */
        Paquete p = PaqueteDAO.leerPaquete(pathPaquete);
        
        /*** PASO 1: Recuperar clave privada del Profesor ***/
        
        /*** Crear KeyFactory (depende del provider) usado para las transformaciones de claves*/
	KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC"); // Hace uso del provider BC
        
        // 1.1 Leer datos binarios PKCS8
	File ficheroClavePrivada = new File(clavePrivadaProfesor); 
	int tamanoFicheroClavePrivada = (int) ficheroClavePrivada.length();
	byte[] bufferPriv = new byte[tamanoFicheroClavePrivada];
	FileInputStream in = new FileInputStream(ficheroClavePrivada);
	in.read(bufferPriv, 0, tamanoFicheroClavePrivada);
	in.close();

	// 1.2 Recuperar clave privada desde datos codificados en formato PKCS8
	PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bufferPriv);
	PrivateKey clavePrivada = keyFactoryRSA.generatePrivate(clavePrivadaSpec);
	System.out.println("\n-------------------------------");
        System.out.println("1.Clave privada PROFESOR recuperada");
        System.out.println("\n-------------------------------");
        
        /*** PASO 2: Crear cifrador RSA para descifrar la clave secreta ***/
        Cipher cifradorRSA = Cipher.getInstance("RSA", "BC"); // Hace uso del provider BC
        
        //2.1: Poner cifrador en modo DESCIFRADO
        cifradorRSA.init(Cipher.DECRYPT_MODE, clavePrivada); // Descrifra con la clave privada
        System.out.println("2. Descifrar con clave privada");
        
        //2.2: Descifrar bloque que contiene la clave secreta
        byte[] bufferSecreta = cifradorRSA.doFinal(p.getContenidoBloque("clave cifrada"));
        
        /*** PASO 3: Recuperar clave secreta del fichero */
        
        /* Crear SecretKeyFactory usado para las transformaciones de claves secretas*/
	SecretKeyFactory secretKeyFactoryDES = SecretKeyFactory.getInstance("DES", "BC");
        
	// 3.2 Cargar clave directamente desde los datos leidos
	DESKeySpec DESspec = new DESKeySpec(bufferSecreta);
	SecretKey claveSecreta = secretKeyFactoryDES.generateSecret(DESspec);
        System.out.println("CLAVE SECRETA RECUPERADA");
        System.out.println("\n-------------------------------");
        
        
        /*** PASO 4: Crear cifrador DES para descifrar examen ***/
        Cipher cifradorDES = Cipher.getInstance("DES/ECB/PKCS5Padding", "BC");
	// Algoritmo DES
	// Modo : ECB (Electronic Code Book)
	// Relleno : PKCS5Padding
	//
        
        //4.1: Poner cifrador en modo DESCIFRADO
        cifradorDES.init(Cipher.DECRYPT_MODE, claveSecreta); // Descrifra con la clave privada
        System.out.println("4. Descifrar con clave privada");
        
        //4.2: Descifrar bloque que contiene el examen
        byte[] examenClaro = cifradorDES.doFinal(p.getContenidoBloque("examen cifrado"));
        System.out.println("EXAMEN RECUPERADO");
        System.out.println("\n-------------------------------");
        
        /***Paso 5: Recuperar clave PUBLICA de la Autoridad de Sellado del fichero ***/
        
        // 5.1 Leer datos binarios x509
	File ficheroClavePublica2 = new File(clavePublicaAutoridad); 
	int tamanoFicheroClavePublica2 = (int) ficheroClavePublica2.length();
	byte[] bufferPub2 = new byte[tamanoFicheroClavePublica2];
	in = new FileInputStream(ficheroClavePublica2);
	in.read(bufferPub2, 0, tamanoFicheroClavePublica2);
	in.close();

	//5.2 Recuperar clave publica desde datos codificados en formato X509
	X509EncodedKeySpec clavePublicaAutoridadSpec = new X509EncodedKeySpec(bufferPub2);
	PublicKey clavePublica2 = keyFactoryRSA.generatePublic(clavePublicaAutoridadSpec);
        System.out.println("7. Clave publica Autoridad de Sellado recuperada");
        System.out.println("\n-------------------------------");
        
        /*** PASO 6: Verificar Sellado del Paquete ***/
        
        /* Creamos la instancia del objeto signature */
        Signature firmador2 = Signature.getInstance("MD5withRSA", "BC");
        
        //6.1: Configuración del objeto Signature en modo VERIFICACION
        firmador2.initVerify(clavePublica2);
        
        //6.2: Alimentar los datos a validar
        firmador2.update(p.getContenidoBloque("fecha"));
        firmador2.update(p.getContenidoBloque("firma"));
        
        //6.3: Verificar la firma
        boolean verificacion2;
        verificacion2 = firmador2.verify(p.getContenidoBloque("sello tiempo firmado"));
        
        if(verificacion2){
            
            //Si el sello se verifica correctamente, mostramos la fecha en que se selló el examen
            String fecha = new String(p.getContenidoBloque("fecha"));
        
            System.out.println("La fecha en que se firmo el paquete es: " + fecha);
            System.out.println("\n-------------------------------");
            
            System.out.println("Sello del paquete verificado CORRECTAMENTE");
            System.out.println("\n-------------------------------");
        }
        else{
            System.out.println("Sello del paquete INCORRECTO, DATOS ALTERADOS");
            System.out.println("\n-------------------------------");
        }
        
        /***Paso 7: Recuperar clave PUBLICA del ALUMNO del fichero ***/
        
        // 7.1 Leer datos binarios x809
	File ficheroClavePublica = new File(clavePublicaAlumno); 
	int tamanoFicheroClavePublica = (int) ficheroClavePublica.length();
	byte[] bufferPub = new byte[tamanoFicheroClavePublica];
	in = new FileInputStream(ficheroClavePublica);
	in.read(bufferPub, 0, tamanoFicheroClavePublica);
	in.close();

	// 7.2 Recuperar clave publica desde datos codificados en formato X509
	X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(bufferPub);
	PublicKey clavePublica = keyFactoryRSA.generatePublic(clavePublicaSpec);
        System.out.println("5. Clave publica ALUMNO recuperada");
        System.out.println("\n-------------------------------");
        
        /*** PASO 8: Verificar firma del ALUMNO del paquete ***/
        
        /* Creamos la instancia del objeto signature */
        Signature firmador = Signature.getInstance("MD5withRSA", "BC");
        
        //8.1: Configuración del objeto Signature en modo VERIFICACION
        firmador.initVerify(clavePublica);
        
        //8.2: Alimentar los datos a validar
        firmador.update(examenClaro);
        
        //8.3: Verificar la firma
        boolean verificacion;
        verificacion = firmador.verify(p.getContenidoBloque("firma"));
        
        if(verificacion){
            
            System.out.println("Firma del paquete verificada CORRECTAMENTE");
            System.out.println("\n-------------------------------");
        }
        else{
            System.out.println("Firma del paquete INCORRECTA, DATOS ALTERADOS");
            System.out.println("\n-------------------------------");
        }
        
        /*** PASO 9: Comprobamos si sello de la Autoridad de Sellado y firma del alumno no se han alterado ***/
        
        if(verificacion && verificacion2){
            
            //9.1: Si es correcto, escribimos Examen en claro a disco
            FileOutputStream out = new FileOutputStream(pathExamenClaro);
            out.write(examenClaro);
            out.close();
            
            System.out.println("Resultado del desempaquetado CORRECTO");
            System.out.println("\n-------------------------------");
        }
        else{
            System.out.println("Resultado del desempaquetado INCORRECTO");
            System.out.println("\n-------------------------------");
        }
        
        
        
        
    }
    
    public static void mensajeAyuda() {
	
        System.out.println("Aplicacion DesempaquetarExamen");
	System.out.println("\tSintaxis:   java DesempaquetarExamen nombre_paquete nombre_examen_con_extension fichero_clave_privada_profesor fichero_clave_publica_alumno fichero_clave_publica_autoridad_de_sellado");
	System.out.println();
    }
}
