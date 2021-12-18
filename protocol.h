#ifndef PROTOCOL_H_INCLUDED
#define PROTOCOL_H_INCLUDED

typedef struct
{
   __u16 dest_port;
   __u32 dest_ip;
   void* max_range;
   void* min_range;
}protocol;


#endif // PROTOCOL_H_INCLUDED
