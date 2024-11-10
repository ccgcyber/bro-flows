
## I include libraries as in the example of the removed packages event in the documentation
## @load base/protocols/conn
## @load base/protocols/http
## global connections: vector of connection;

###########################################################################
## First approach with a single set, just store the packets in a set and when they die I delete them
## Change from vector to set for comparisons, the vector type in bro does not support them
global conex: set[connection];
## Global variable to know the size of the set
global tams=0;
## Global variable to know the number of packets in the pcap file
global tam=0;
## Variable to see the packages we removed and check if they are the same as the ones we added
global elimi=0;

## Second approach... FILE approx2.bro I CREATE A COMPLEMENTARY SET TO STORE THOSE THAT I ALREADY HAVE STORED AT SOME POINT

## I create an auxiliary function to see the information of the new package that is added, not of all the packages all the time
function informacion_paquete(c: connection){
    print fmt("New IP package information: %s , Po: %s , IPd: %s , Pd: %s ", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
}

## Every time a new package comes in I compare it to what I already have in the set
event new_connection(c: connection){

## We add one to be able to see the total number of packages we have
tam=tam+1;
## If the set is empty I put the first package
if(|conex|==0){
   add conex[c];
  }
## I create a local connection to be able to make comparisons with the set and to be able to discard packets
local cd: connection;
## Boolean variable to control access to the set
local met = F;
## If the set is empty we allow writing
if(|conex|==0){
    add conex[c];
    tams=tams+1;
  }

## for which he goes around the set and makes comparisons
for(s in conex){
    ## We copy into the local variable to compare with everything in the set
    cd=s;
    if(cd$id$orig_h != c$id$orig_h){
      if(cd$id$resp_h != c$id$resp_h){
        if(cd$id$orig_p != c$id$orig_p){
          if(cd$id$resp_p != c$id$resp_p){
            ## If all conditions are met the boolean variable controlling access to the set is changed to true, T
            met=T;
          }
        }
      }
    }

  }
  ## With the boolean variable we control the growth of the set
  if (met==T){
    add conex[c];
    tams=tams+1;
    print fmt("I put a new packet through the different source connection");
  }
  met=F;
  print fmt("Number of packages at the moment: %d", tam);
  print fmt("Set size: %d", tams);
  informacion_paquete(c);
}

## when the connection is deleted
## the same packets are obtained when added as when deleted, therefore we must control when we add it and when we delete it
event connection_state_remove(c: connection){

##  print fmt("Connection deleted : %s", c$id$orig_h);
##  elimi=elimi+1;
##  print fmt("Number of packages removed: %d", elimi);

  ## I create a local connection to be able to make comparisons with the set and to be able to discard packets
    local cd: connection;
  ## Boolean variable to control access to the set
    local met = F;

  ## for which he goes around the set and makes comparisons
    for(s in conex){
      ## We copy into the local variable to compare with everything in the set
      cd=s;
      if(cd$id$orig_h == c$id$orig_h){
        if(cd$id$resp_h == c$id$resp_h){
          if(cd$id$orig_p == c$id$orig_p){
            if(cd$id$resp_p == c$id$resp_p){
              ## If all conditions are met the boolean variable controlling access to the set is changed to true, T
              met=T;
            }
          }
        }
      }

    }
    ## With the boolean variable we control the decrease of the set
    if (met==T){
      delete conex[c];
      elimi=elimi+1;
    ## We check that the size we manage per screen of the set is not less than 0 so that it does not give garbage values
      if(tams==0){
        tams=0;
      }
      if(tams>0){
        tams=tams-1;
      }
    ## We display a message on the screen about the removal of a package if necessary
      print fmt("I drop a packet because of the different source connection");
    }
    met=F;
    print fmt("Number of packages at the moment: %d", tam);
    print fmt("Set size: %d", tams);
    informacion_paquete(c);
    ## print fmt("Number of packages in set: %d", |conex|);
}

## Event that is fired when BRO ends
event bro_done(){
  print fmt("Number of packages in set: %d", |conex|);
}
