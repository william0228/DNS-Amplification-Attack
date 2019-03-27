all : DNS_Amplification_Attack.c
	gcc DNS_Amplification_Attack.c -o DNS_Amplification_Attack
clean :
	rm -f DNS_Amplification_Attack