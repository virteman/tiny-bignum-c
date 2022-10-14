#include <stdio.h>
#include <stdlib.h>
#include "tiny_rsa.h"


static void test_rsa1024(void) {
  char n_hexstr[]  = "B3CAC1D59A46A6552E6FE1A32432C872B52B524EBE010498AFB1A4A5D7DD74F9DFF52564953550256629AF45CE616E2893D45134066E22A63A941E881F1EA7D588F8972995418B5000A85741869313C6F8E11B2F5B45DBEC414DB46CE4470857C04805DC4E062C96AE1B6E876C3BFFDB72CA949ADD124B09235E3023215DF7D3";
  char d_hexstr[] = "9A33AF75D580FCCE182AEB3A7224801929DB8317780D057533534824D974DE0C26126AC4CED84FEA13AA72E28B34B337683AF47E8B79508C83B7604C5D6C7C82CF86E12C04CC8577CF5EB40599C2FB89FDB37D982EF05E4055EC7E3D594ECD7754759775268F25A1A09E4F92EA1AC26999E191D5D17A0F0499A8EBE112F2D461";
  int e = 65537;
  char buf[512];

  p_tiny_rsa trsa = &(tiny_rsa){};
  init_tiny_rsa(trsa, n_hexstr, e, d_hexstr);
  printf("inited \n");
  char plain_txt[] = "woshishui";
  /*
  pub_encrypt(trsa, plain_txt, buf);
  printf("Encrypt plain text [%s] to cipher text[%s] \n", plain_txt, buf);
  priv_decrypt(trsa, buf, plain_txt);
  printf("Decrypt cipher text[%s] to plain text[%s] \n", buf, plain_txt);
  */
  //////////////////////////////////
  priv_encrypt(trsa, plain_txt, buf);
  printf("priv Encrypt plain text [%s] to cipher text[%s] \n", plain_txt, buf);
  pub_decrypt(trsa, buf, plain_txt);
  printf("pub Decrypt cipher text[%s] to plain text[%s] \n", buf, plain_txt);
}


int main()
{
  printf("\n");
  printf("Testing RSA encryption implemented with bignum. \n");

  test_rsa1024();

  printf("\n");
  printf("\n");



  return 0;
}


