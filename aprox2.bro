
## Incluyo librerias como en el ejemplo del evento de paquetes eliminados de la documentacion
## @load base/protocols/conn
## @load base/protocols/http
##global conexiones: vector of connection;

## PRIMERA APROXIMACION con un solo set, simplemente almaceno los paquetes en un set (PARA FLUJOS ACTIVOS) y cuando mueren los elimino
## El contenido del set si se ve alterado, pero el tamaño no, pues no es memoria dinamica
## Cambio de vector a set por las comparaciones, el tipo vector en bro no las soporta
global conex: set[connection];
## Variable global para conocer el tamaño del set
global tams=0;
## Variable global para conocer el numero de paquetes que hay en el archivo pcap
global tam=0;
## Variable para ver los paquetes que eliminamos y comprobar si son los mismos que los que hemos añadido
global elimi=0;

## SEGUNDA APROXIMACION... FICHERO aprox2.bro CREO SET COMPLEMENTARIO PARA ALMACENAR LOS QUE YA TENGO ALMACENADOS EN ALGUN MOMENTO

## set para almacenar los paquetes que coinciden con los que ya tenemos en conex... (PARA FLUJOS EMPAREJADOS)
## Incluidos TCP, UDP e ICMP
global matchs: set[connection]; ## Tal vez una table con indice connection para saber con cual esta emparejado (?)
## variable global para controlar su crecimiento
global tamm=0;
## variable global para ver la cantidad de matchs distintos que hacemos
global nmatchs=0;

## TERCERA APROXIMACION... CREO TABLE PARA ALMACENAR EN EL INDICE LA INFORMACION DEL PRIMER SET Y METERLE LA INFORMACION DEL SEGUNDO CUANDO CASEN.
global empa: table[connection] of connection;

## TODO: umbral mediante el cual comparar los flujos
##        comprobar como se organiza internamente un set, si cuando se borra algo el indice baja o no...

## Creo funcion auxiliar para ver la informacion del paquete nuevo que se añade, no de todos los paquetes todo el rato
function informacion_paquete(c: connection){
    print fmt("Informacion del paquete nuevo IPo: %s , Po: %s , IPd: %s , Pd: %s ", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
}
## Esta funcion es solo para depuracion, al final sera borrada
## Creo funcion auxiliar para ver la informacion del paquete que se coincide
function informacion_coincidencia(c: connection, p: connection){
    print fmt("       Informacion del primer paquete  IPo: %s , Po: %s , IPd: %s , Pd: %s ", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
    print fmt("Informacion del paquete coincidente  IPo: %s , Po: %s , IPd: %s , Pd: %s ", p$id$orig_h, p$id$orig_p, p$id$resp_h, p$id$resp_p);
}


## Cada vez que entra un nuevo paquete lo comparo con lo que ya tengo en el set
## Este evento se lanza con cada nueva conexion de un flujo que no sea conocido
## Generated for every new connection. This event is raised with the first packet of a previously unknown connection. Bro uses a flow-based definition of “connection” here that includes not only TCP sessions but also UDP and ICMP flows.
event new_connection(c: connection){

## Si el set esta vacio meto el primer paquete
  if(tam==0){
   add conex[c];
  }
  ## Sumamos uno para poder ver el numero de paquetes totales que tenemos
    tam=tam+1;
## Creo un connection local para poder hacer comparaciones con el set y poder descartar paquetes
  local cl: connection;
## Variable booleana para controlar el acceso al set
  local met = F;
## Si el set está vacio le permitimos escritura
##  if(|conex|==0){
##    add conex[c];
##    tams=tams+1;
##  }

## for que va recorriendo el set y haciendo comparaciones
  for(s in conex){
    ## Copiamos en la variable local para comparar con todo lo que hay en el set
    cl=s;
    if(cl$id$orig_h != c$id$orig_h){
      if(cl$id$resp_h != c$id$resp_h){
        if(cl$id$orig_p != c$id$orig_p){
          if(cl$id$resp_p != c$id$resp_p){
            ## Si se dan todas las condiciones la variable booleana de control de acceso al set se cambia a true, T
            met=T;
          }
        }
      }
    }

  }
  ## Con la variable booleana controlamos el crecimiento del set
  if (met==T){
    add conex[c];
    tams=tams+1;
    print fmt("Meto un paquete nuevo por la conexion de origen distinta");
  }
  met=F;
  print fmt("Numero de paquetes al momento: %d", tam);
  print fmt("Tamanio del set: %d", tams);
  informacion_paquete(c);
}

## cuando la conexion es borrada
## se obtienen los mismos paquetes añadidos que eliminados, por lo tanto hay que controlar cuando lo añadimos y cuando lo eliminamos
## Sirve para TCP, UDP e ICMP
event connection_state_remove(c: connection){

##  print fmt("Conexion eliminada : %s", c$id$orig_h);
##  elimi=elimi+1;
##  print fmt("Numero de paquetes eliminados: %d", elimi);


  ## Creo un connection local para poder hacer comparaciones con el set y poder descartar paquetes
    local cl: connection;
  ## Variable booleana para controlar el acceso al set
    local met = F;

  ## for que va recorriendo el set y haciendo comparaciones
    for(s in conex){
      ## Copiamos en la variable local para comparar con todo lo que hay en el set
      cl=s;
      if(cl$id$orig_h == c$id$orig_h){
        if(cl$id$resp_h == c$id$resp_h){
          if(cl$id$orig_p == c$id$orig_p){
            if(cl$id$resp_p == c$id$resp_p){
              ## Si se dan todas las condiciones la variable booleana de control de acceso al set se cambia a true, T
              met=T;
            }
          }
        }
      }

    }
    ## Con la variable booleana controlamos el decrecimiento del set
    if (met==T){
      delete conex[c];
      elimi=elimi+1;
    ## Controlamos que el tamaño que manejamos por pantalla del set no sea menor que 0 para que no de valores basura
      if(tams==0){
        tams=0;
      }
      if(tams>0){
        tams=tams-1;
      }
    ## Mostramos por pantalla un mensaje de eliminacion de un paquete si procede
      print fmt("Elimino un paquete TCP por la conexion de origen distinta");
    }
    met=F;
    print fmt("Numero de paquetes al momento: %d", tam);
    print fmt("Tamanio del set: %d", tams);
    informacion_paquete(c);
    ## print fmt("Numero de paquetes en set: %d", |conex|);
}

## Cuando la conexion se establece vemos si hay paquetes que emparejar y los metemos en matchs
## Solo sirve para conexiones TCP, se genera cuando ve un SYN-ACK que responde al handshake de un TCP
event connection_established(c: connection){

  ## Si el set esta vacio meto el primer paquete
  ## ¿Se puede eliminar?
    if(tam==0){
     add conex[c];
    }
  ## Creo un connection local para poder hacer comparaciones con el set y poder descartar paquetes que no coinciden
    local cl: connection;
  ## Variable booleana para controlar el acceso al set
    local met = F;

  ## for que va recorriendo el set y haciendo comparaciones
    for(s in conex){
      ## Copiamos en la variable local para comparar con todo lo que hay en el set
      cl=s;
      if(cl$id$orig_h == c$id$orig_h){
        if(cl$id$resp_h == c$id$resp_h){
          if(cl$id$orig_p == c$id$orig_p){
            if(cl$id$resp_p == c$id$resp_p){
              ## Si se dan todas las condiciones la variable booleana de control de acceso al set se cambia a true, T
              met=T;
              ## Cambiar para que no se vea toda la informacion del paquete, solo las IP's y los puertos
              informacion_coincidencia(c, cl);

            }
          }
        }
      }

    }
    ## Con la variable booleana controlamos el crecimiento del set
    if (met==T){
      add matchs[c];
      tamm=tamm+1;
      print fmt("Encontrado un paquete TCP que coincide con otro de las conexiones que ya tenemos");
      nmatchs=nmatchs+1;
    }
    met=F;
    print fmt("Tamanio del set matchs: %d", tamm);
    informacion_paquete(c);

}

## Para protocolo UDP usaremos otro evento
## Son funciones muy costosas por lo que se deberia de evitar su uso a menos que sea necesario
## udp_reply se lanza por cada paquete UDP del flujo que es devuelto por el destinatario del primer envio.
## event udp_reply(u: connection)
## udp_request se lanza por cada paquete UDP del flujo que es enviado por el origen.
event udp_request(u: connection){

    ## Si el set esta vacio meto el primer paquete
    ## ¿Se puede eliminar?
      if(tam==0){
       add conex[u];
      }
    ## Creo un connection local para poder hacer comparaciones con el set y poder descartar paquetes que no coinciden
      local ul: connection;
    ## Variable booleana para controlar el acceso al set
      local met = F;

    ## for que va recorriendo el set y haciendo comparaciones
      for(s in conex){
        ## Copiamos en la variable local para comparar con todo lo que hay en el set
        ul=s;

        if(ul$id$orig_h == u$id$orig_h){
          if(ul$id$resp_h == u$id$resp_h){
            if(ul$id$orig_p == u$id$orig_p){
              if(ul$id$resp_p == u$id$resp_p){
                ## Si se dan todas las condiciones la variable booleana de control de acceso al set se cambia a true, T
                met=T;
                ## Cambiar para que no se vea toda la informacion del paquete, solo las IP's y los puertos
                informacion_coincidencia(u, ul);

              }
            }
          }
        }

      }
      ## Con la variable booleana controlamos el crecimiento del set
      if (met==T){
        add matchs[u];
        tamm=tamm+1;
        print fmt("Encontrado un paquete UDP request que coincide con otro de las conexiones que ya tenemos");
        nmatchs=nmatchs+1;
      }
      met=F;
      print fmt("Tamanio del set matchs: %d", tamm);
      informacion_paquete(u);

}

event udp_reply(u: connection){
  ## Si el set esta vacio meto el primer paquete
  ## ¿Se puede eliminar?
    if(tam==0){
     add conex[u];
    }
  ## Creo un connection local para poder hacer comparaciones con el set y poder descartar paquetes que no coinciden
    local ul: connection;
  ## Variable booleana para controlar el acceso al set
    local met = F;

  ## for que va recorriendo el set y haciendo comparaciones
    for(s in conex){
      ## Copiamos en la variable local para comparar con todo lo que hay en el set
      ul=s;

      if(ul$id$orig_h == u$id$orig_h){
        if(ul$id$resp_h == u$id$resp_h){
          if(ul$id$orig_p == u$id$orig_p){
            if(ul$id$resp_p == u$id$resp_p){
              ## Si se dan todas las condiciones la variable booleana de control de acceso al set se cambia a true, T
              met=T;
              ## Cambiar para que no se vea toda la informacion del paquete, solo las IP's y los puertos
              informacion_coincidencia(u, ul);

            }
          }
        }
      }

    }
    ## Con la variable booleana controlamos el crecimiento del set
    if (met==T){
      add matchs[u];
      tamm=tamm+1;
      print fmt("Encontrado un paquete UDP reply que coincide con otro de las conexiones que ya tenemos");
      nmatchs=nmatchs+1;
    }
    met=F;
    print fmt("Tamanio del set matchs: %d", tamm);
    informacion_paquete(u);

}


## udp_session_done se lanza cuando la conexion UDP finaliza, por lo tanto tendremos que borrar del set conex los paquetes que se correspondan
## event udp_session_done(u: connection)
## Segun la documentacion esto es soportado por los siguientes protocolos DNS, NTP, Netbios, Syslog, AYIYA, Teredo y GTPv1.


## Para mensajes ICMP, tendremos que usar otro tipo de evento especifico para este tipo
## ICMP manda mensajes de echo, el primero de tipo request, mensaje de control para recibir un mensaje reply
## icmp_echo_request Type:	event (c: connection, icmp: icmp_conn, id: count, seq: count, payload: string)
## ICMP manda el reply una vez que se manda el request
## icmp_echo_reply Type:	event (c: connection, icmp: icmp_conn, id: count, seq: count, payload: string)
## Habra que tener en cuenta que no se exceda el payload
## icmp_conn extiende la informacion de connection, en esta aproximacion no sera necesario usarlo
## Segun la documentacion la descripcion de las variables para los dos eventos son:
## c:	The connection record for the corresponding ICMP flow.
## icmp:	Additional ICMP-specific information augmenting the standard connection record c.
## id:	The echo reply identifier.
## seq:	The echo reply sequence number.
## payload:	The message-specific data of the packet payload, i.e., everything after the first 8 bytes of the ICMP header.

event icmp_echo_request(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string){

  ## Si el set esta vacio meto el primer paquete
  ## ¿Se puede eliminar?
    if(tam==0){
     add conex[c];
    }
  ## Creo un connection local para poder hacer comparaciones con el set y poder descartar paquetes que no coinciden
    local cl: connection;
  ## Variable booleana para controlar el acceso al set
    local met = F;

  ## for que va recorriendo el set y haciendo comparaciones
    for(s in conex){
      ## Copiamos en la variable local para comparar con todo lo que hay en el set
      cl=s;

      if(cl$id$orig_h == c$id$orig_h){
        if(cl$id$resp_h == c$id$resp_h){
          if(cl$id$orig_p == c$id$orig_p){
            if(cl$id$resp_p == c$id$resp_p){
              ## Si se dan todas las condiciones la variable booleana de control de acceso al set se cambia a true, T
              met=T;
              ## Cambiar para que no se vea toda la informacion del paquete, solo las IP's y los puertos
              informacion_coincidencia(c, cl);

            }
          }
        }
      }

    }
    ## Con la variable booleana controlamos el crecimiento del set
    if (met==T){
      add matchs[c];
      tamm=tamm+1;
      print fmt("Encontrado un paquete ICMP request que coincide con otro de las conexiones que ya tenemos");
      nmatchs=nmatchs+1;
    }
    met=F;
    print fmt("Tamanio del set matchs: %d", tamm);
    informacion_paquete(c);

}

event icmp_echo_reply(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string){

  ## Si el set esta vacio meto el primer paquete
  ## ¿Se puede eliminar?
    if(tam==0){
     add conex[c];
    }
  ## Creo un connection local para poder hacer comparaciones con el set y poder descartar paquetes que no coinciden
    local cl: connection;
  ## Variable booleana para controlar el acceso al set
    local met = F;

  ## for que va recorriendo el set y haciendo comparaciones
    for(s in conex){
      ## Copiamos en la variable local para comparar con todo lo que hay en el set
      cl=s;

      if(cl$id$orig_h == c$id$orig_h){
        if(cl$id$resp_h == c$id$resp_h){
          if(cl$id$orig_p == c$id$orig_p){
            if(cl$id$resp_p == c$id$resp_p){
              ## Si se dan todas las condiciones la variable booleana de control de acceso al set se cambia a true, T
              met=T;
              ## Cambiar para que no se vea toda la informacion del paquete, solo las IP's y los puertos
              informacion_coincidencia(c, cl);

            }
          }
        }
      }

    }
    ## Con la variable booleana controlamos el crecimiento del set
    if (met==T){
      add matchs[c];
      tamm=tamm+1;
      print fmt("Encontrado un paquete ICMP reply que coincide con otro de las conexiones que ya tenemos");

    }
    met=F;
    print fmt("Tamanio del set matchs: %d", tamm);
    informacion_paquete(c);
    nmatchs=nmatchs+1;
}
## Evento que se genera cuando BRO va a tenerminar, menos si se realiza mediante una llamada a la funcion exit (ver documentacion)
event bro_done(){
  print fmt("El numero total de coincidencias es: %d", nmatchs);
  print fmt("El tamaño maximo del set de coincidencias es: %d", |matchs|);
}
