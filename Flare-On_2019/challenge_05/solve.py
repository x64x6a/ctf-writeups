"""
moar_pouetry@flare-on.com
"""


"""
int sub_42038A()
{
  char v1; // [esp+80h] [ebp-180h]
  char v2; // [esp+C0h] [ebp-140h]
  char v3; // [esp+100h] [ebp-100h]
  char v4; // [esp+140h] [ebp-C0h]
  char v5; // [esp+180h] [ebp-80h]
  char v6; // [esp+1C0h] [ebp-40h]

  ((*dev_interface)->Clear)(dev_interface, 0, 0, 7, 0, 1065353216, 0);
  (*dev_interface)->BeginScene(dev_interface);
  (*dev_interface)->SetFVF(dev_interface, 18);
  D3DXMatrixLookAtLH(&v6, &unk_420604, &unk_430058, &unk_421CE4);
  (*dev_interface)->SetTransform(dev_interface, D3DTS_VIEW, &v6);
  D3DXMatrixPerspectiveFovLH(&v5, 1061752795, 1068149419, 1065353216, 1133903872);
  (*dev_interface)->SetTransform(dev_interface, D3DTS_PROJECTION, &v5);
  D3DXMatrixTranslation(&v3, 0, 0, 1125515264);
  *&dword_430040 = *&dword_430040 + *&dword_420570;
  D3DXMatrixRotationY(&v4, dword_430040);
  *&dword_430044 = *&dword_430044 + *&dword_42057C;
  D3DXMatrixRotationY(&v2, dword_430044);
  (*dev_interface)->SetMaterial(dev_interface, &unk_4205C0);
  (*dev_interface)->SetTransform(dev_interface, 256, &v4);
  (*(*dword_430050 + 12))(dword_430050, 0);
  D3DXMatrixMultiply(&v1, &v2, &v3);
  (*dev_interface)->SetTransform(dev_interface, 256, &v1);
  (*(*dword_430054 + 12))(dword_430054, 0);
  (*dev_interface)->EndScene(dev_interface);
  return (*dev_interface)->Present(dev_interface, 0, 0, 0, 0);
}


patch the `SetTransform` on the multiplied matrix with NOPs, the flag will then display

moar_pouetry@flare-on.com
"""