#ifndef PROTOCOL_H_INCLUDED
#define PROTOCOL_H_INCLUDED

typedef struct
{
   __u16 dest_port;
   __u32 dest_ip;
   char* type;
   void* min_range;
   void* max_range;
   int serialNumber;
}protocol;


#endif // PROTOCOL_H_INCLUDED
