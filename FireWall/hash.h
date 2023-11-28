typedef struct
{
    unsigned char flags;
    unsigned short src_port;
    unsigned short dst_port;
    unsigned src_IP;
    unsigned dst_IP;
    unsigned first_FIN;
} TCP_connection;

typedef struct
{
    unsigned short src_port;
    unsigned short dst_port;
    unsigned src_IP;
    unsigned dst_IP;
    unsigned long time;
} UDP_connection;

typedef struct
{
    unsigned src_IP;
    unsigned dst_IP;
    unsigned long time;
} ICMP_connection;

unsigned char my_hash_32(unsigned key)
{
    int i, j;
    unsigned mask;
    unsigned char part, value = 0;
    for (i = 0; i < 4; ++i)
    {
        part = 0;
        for (mask = 1 << i, j = 0; j < 8; mask <<= 4, ++j)
        {
            part = (part << 1) ^ ((key & mask) >> ((j << 2) + i));
        }
        value ^= part;
    }
    return value;
}

unsigned char my_hash_16(unsigned short key)
{
    int i, j;
    unsigned short mask;
    unsigned char part, value = 0;
    for (i = 0; i < 2; ++i)
    {
        part = 0;
        for (mask = 1 << i, j = 0; j < 8; mask <<= 2, ++j)
        {
            part = (part << 1) ^ ((key & mask) >> ((j << 1) + i));
        }
        value ^= part;
    }
    return value;
}