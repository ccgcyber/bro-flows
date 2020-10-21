# Change from vector to set by comparisons, the vector type in bro does not support them

global conex: set[connection];
global tam=0;

### package ???, maybe a packet
# Every time a new package comes in, compare it to what is already in a set

event new_connection(c: connection){
   # If the set is empty I put the first package
   add conex[c];
   tam=tam+1;
   print fmt("Total number of packages = %d",|conex|);
   print fmt("Size count: %d", tam);

}
