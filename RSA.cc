// Implementation of the RSA public-key encryption algorithm
// ECE4893/ECE8893, Fall 2012

#include "gmpxx.h"
#include <iostream>

using namespace std;

void get_rand_prime(mpz_class& rand_prime, unsigned long sz);
bool Is_gcd_1(const mpz_class& d,const mpz_class& phi_n);
bool mul_inverse_exists(mpz_class& e, const mpz_class& d,const mpz_class& phi_n);
void perform_RSA(mpz_class& c, const mpz_class& m, const mpz_class& d, const mpz_class& n);

#define DEBUG 0
#define PRIME_TEST_ATTEMPTS 100
#define SIZE                1024
#define KEYPAIRS            10
#define MESSAGES            10


gmp_randclass r(gmp_randinit_default);


void generate_random_seed(void)
{
  unsigned long int rand;
  FILE *fp;
  fp = fopen("/dev/random", "r");
  fread(&rand, 1, sizeof(unsigned long int), fp);
  r.seed(rand);
  fclose(fp);
}


void get_rand_prime(mpz_class& rand_prime, unsigned long sz)
{
  while(1)
  {
    rand_prime = r.get_z_bits(sz);
    if(0 != mpz_probab_prime_p(rand_prime.get_mpz_t(),PRIME_TEST_ATTEMPTS))
    {
      break;
    }
  }

}


bool Is_gcd_1(const mpz_class& d,const mpz_class& phi_n)
{
  mpz_class gcd;  

  mpz_gcd(gcd.get_mpz_t(), d.get_mpz_t(), phi_n.get_mpz_t());

  if(1 == gcd)
  {
    return true;
  }
  
  return false;    
}


bool mul_inverse_exists(mpz_class& e, const mpz_class& d,const mpz_class& phi_n)
{
  if(0 != mpz_invert(e.get_mpz_t(), d.get_mpz_t(), phi_n.get_mpz_t()))
  {
    return true;
  }

  return false;
}


void perform_RSA(mpz_class& c, const mpz_class& m, const mpz_class& d, const mpz_class& n)
{
  mpz_powm(c.get_mpz_t(), m.get_mpz_t(), d.get_mpz_t(), n.get_mpz_t());
}


/*int main()
{
  generate_random_seed();

  mpz_class p;
  get_rand_prime(p, 32);    
  mpz_class q;
  get_rand_prime(q, 32);
  
  mpz_class N = p*q;
       
  cout << "p:      " << p << "  ::q:      " << q << endl;
 
  unsigned long int n = 1;
  
  mpz_class d_n, x_n = r.get_z_bits(32);
  while(1)
  { 
    n++;
    mpz_powm_ui(x_n.get_mpz_t(), x_n.get_mpz_t(), n, N.get_mpz_t());
    mpz_gcd_ui(d_n.get_mpz_t(), N.get_mpz_t(), x_n.get_ui()-1);
    if((d_n>1) && (d_n<N))
    {
      break;
    }
  }
   
  mpz_class p_calc, q_calc;
  
  q_calc = d_n;
  p_calc = N/d_n;

  cout << "p_calc: " << p_calc << "  ::q_calc: " << q_calc << endl;

  return 0;
}*/



int main()
{
  // Your code here
  unsigned int decripted_success=0, decripted_fail=0;

  generate_random_seed();

  for(unsigned long sz = 32; sz<=SIZE; sz*=2)
  {
    bool first_key_pair_mssg = true;
    for(unsigned int keypairs=0; keypairs<KEYPAIRS; keypairs++)
    {
      for(unsigned message=0; message<MESSAGES; message++)
      {
        mpz_class p;
        get_rand_prime(p, sz);    
        mpz_class q;
        get_rand_prime(q, sz);
  
        mpz_class n = p*q;
        mpz_class phi_n = (p-1) * (q-1);
        
        #if 1==DEBUG
          cout << "p: " << p << endl;
          cout << "q: " << q << endl;
          cout << "n: " << n << endl;
          cout << "phi(n): " << phi_n << endl;
        #endif 
       
        mpz_class d;
        while(1)
        {
          d = r.get_z_bits(sz*2);
          if( (d < phi_n) && (true == Is_gcd_1(d,phi_n)) ) 
          {
            break;
          }
        }
    
        mpz_class e;
        if(false == mul_inverse_exists(e, d, phi_n))
        {
          cout << "Error.. Multiplicative inverse doesn't exist for d and phi(n)" << endl;
          break;
        }
        
        #if 1==DEBUG
          cout << "d: " << d << endl;
          cout << "e: " << e << endl;
        #endif
 
        mpz_class m = r.get_z_bits(mpz_sizeinbase(n.get_mpz_t(),2)-1);
    
        mpz_class c;
        perform_RSA(c, m, d, n);
    
        mpz_class m_prime;
        perform_RSA(m_prime, c, e, n);
        
        #if 1==DEBUG
          cout << "Message: " << m << endl;
          cout << "Decripted Message: " << m_prime << endl;
          if(m == m_prime)
          {
            cout << "Message succesfully decripted!!" << endl;
          }
          else
          {
            cout << "Message not decripted!!" << endl;
          }
  
          if(m == m_prime)
          {
            decripted_success++; 
          }
          else
          {
            decripted_fail++;
          }
        #endif
        
        
        
        if(true == first_key_pair_mssg)
        {
          cout << "mpz_class p" << sz << "(\"" << p << "\");" << endl;
          cout << "mpz_class q" << sz << "(\"" << q << "\");" << endl;
          cout << "mpz_class n" << sz << "(\"" << n << "\");" << endl;
          cout << "mpz_class d" << sz << "(\"" << d << "\");" << endl;
          cout << "mpz_class e" << sz << "(\"" << e << "\");" << endl;
          cout << "mpz_class M" << sz << "(\"" << m << "\");" << endl;
          cout << "mpz_class C" << sz << "(\"" << c << "\");" << endl;  
          
          if(32==sz)
          {
            //Break the algorithm
            unsigned long int i = 1;

            mpz_class d_i, x_i = r.get_z_bits(32);
            while(1)
            {
              i++;
              mpz_powm_ui(x_i.get_mpz_t(), x_i.get_mpz_t(), i, n.get_mpz_t());
              mpz_gcd_ui(d_i.get_mpz_t(), n.get_mpz_t(), x_i.get_ui()-1);
              if((d_i>1) && (d_i<n))
              {
                break;
              }
            }

            mpz_class p32_Attack, q32_Attack;

            p32_Attack = d_i;
            q32_Attack = n/d_i;
            
            #if 1==DEBUG
              cout << "p32_Attack: " << p32_Attack << "  ::q32_Attack: " << q32_Attack << endl;
            #endif

            mpz_class phi_n64_Attack;
            phi_n64_Attack = (p32_Attack-1) * (q32_Attack-1);

            mpz_class e32_Attack;
            if(false == mul_inverse_exists(e32_Attack, d, phi_n64_Attack))
            {
              cout << "Error.. Multiplicative inverse doesn't exist for d and phi(n)" << endl;
              break;
            }
            
            mpz_class m_Attack;
            perform_RSA(m_Attack, c, e32_Attack, n);
            
            cout << "mpz_class p32_Attack" << sz << "(\"" << p32_Attack << "\");" << endl;
            cout << "mpz_class q32_Attack" << sz << "(\"" << q32_Attack << "\");" << endl;
            cout << "mpz_class n32_Attack" << sz << "(\"" << n << "\");" << endl;
            cout << "mpz_class d32_Attack" << sz << "(\"" << d << "\");" << endl;
            cout << "mpz_class e32_Attack" << sz << "(\"" << e32_Attack << "\");" << endl;
            cout << "mpz_class C32_Attack" << sz << "(\"" << c << "\");" << endl;
            cout << "mpz_class M32_Attack" << sz << "(\"" << m_Attack << "\");" << endl;

          }
 
          first_key_pair_mssg = false;
        }
      }
    }  
  }
  
  #if 1==DEBUG
    cout << "Succesfully decripted: " << decripted_success << " messages" << endl;
    cout << "Could not decript: " << decripted_fail << " messages" << endl;
  #endif

  return 1;
}

