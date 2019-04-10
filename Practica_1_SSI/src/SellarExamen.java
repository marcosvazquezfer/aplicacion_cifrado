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
import java.util.Calendar;
import java.util.Date;

import javax.crypto.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SellarExamen {
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws FileNotFoundException, IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        // TODO code application logic here
        
        // Comprobar argumentos
        if (args.length != 2) {
                
                mensajeAyuda();
                System.exit(1);
        }
        
        String pathPaquete = args[0];
        String claveAutoridad = args[1];
        
        /* Cargar "provider" BC */
	Security.addProvider(new BouncyCastleProvider());
        
        Paquete paquete = PaqueteDAO.leerPaquete(pathPaquete);
        
        /*** PASO 1: Recuperar clave privada de la Autoridad de Sellado del fichero ***/
            
        /*** Crear KeyFactory (depende del provider) usado para las transformaciones de claves*/
	KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC"); // Hace uso del provider BC
        
	// 1.1 Leer datos binarios PKCS8
	File ficheroClavePrivada = new File(claveAutoridad); 
	int tamanoFicheroClavePrivada = (int) ficheroClavePrivada.length();
	byte[] bufferPriv = new byte[tamanoFicheroClavePrivada];
	FileInputStream in = new FileInputStream(ficheroClavePrivada);
	in.read(bufferPriv, 0, tamanoFicheroClavePrivada);
	in.close();

	// 1.2 Recuperar clave privada desde datos codificados en formato PKCS8
	PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bufferPriv);
	PrivateKey clavePrivada2 = keyFactoryRSA.generatePrivate(clavePrivadaSpec);
	System.out.println("\n-------------------------------");
        System.out.println("1.Clave privada recuperada");
        System.out.println("\n-------------------------------");
		
	/*** PASO 2: Configurar objeto Signature en modo FIRMA, firmar datos y añadir la firma al paquete ***/
		
	/* Creamos la instancia del objeto signature */
        Signature firmador = Signature.getInstance("MD5withRSA", "BC");
		
	//2.1: Configuramos el objeto Signature en modo firma
	firmador.initSign(clavePrivada2);
		
        /***CREAR FECHA***/
        Date fecha = Calendar.getInstance().getTime();
        byte[] bufferFecha = fecha.toString().getBytes();
        
        //2.2: Alimentamos los datos a firmar
	firmador.update(bufferFecha);
        firmador.update(paquete.getContenidoBloque("firma"));
        
        //2.3: Generar y recuperar firma
        byte[] selloFirmado = firmador.sign();
        
        /*** AÑADIR FECHA Y SELLO AL PAQUETE ***/
        paquete.anadirBloque("fecha", bufferFecha);
        paquete.anadirBloque("sello tiempo firmado", selloFirmado);
        
        System.out.println("2.Fecha y Sello añadidos al paquete");
        System.out.println("\n-------------------------------");
        
        /*** PASO 3: Escribir paquete con los bloques generados en disco ***/
        PaqueteDAO.escribirPaquete(pathPaquete, paquete);
    }
    
    public static void mensajeAyuda(){

	System.out.println("Aplicacion SellarExamen");
	System.out.println("\tSintaxis:   java SellarExamen nombre_paquete fichero_clave_privada_autoridad_de_sellado");
	System.out.println();
    }
}
