#ifndef hatchery_h__
#define hatchery_h__

#ifdef __x86_64__

#define REGISTERS struct user_regs_struct

#endif // __x86_64__

#ifdef __arm__

#define REGISTERS struct user_regs

#endif // __arm__

extern unsigned char * hatch_code (unsigned char *code);

#endif // hatchery_h__
