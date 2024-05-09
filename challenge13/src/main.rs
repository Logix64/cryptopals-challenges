use rand::{thread_rng, Rng};
use tools::{encode::{ascii::to_ascii, uri::{from_uri, to_json}}, encrypt::{aes::Aes128, cipher::{CipherCore, CipherMode, ECBMode}}};

fn profile_for( email : &str ) -> Result<String,&'static str> {    
    if email.contains('&') || email.contains('=') {
        Err("characters \"&\" and \"=\" are not allowed.")
    } else {
        Ok(String::from_iter(["email=", email, "&uid=10&role=user"])) 
    }
}

struct CutAndPasteOracle{
    key : Vec<u8>
}

impl CutAndPasteOracle{
    fn new<T : CipherCore>( key : Vec<u8> ) -> Self {
        assert_eq!(key.len(), T::BYTES);
        CutAndPasteOracle{ key }
    }

    fn encrypt<T : CipherCore>( &self, email : &str, output : &mut Vec<u8> ) -> Result<(),&'static str> {
        
        profile_for(email).map(|v| {
            let mut ecb = ECBMode::<T>::init(&self.key, CipherMode::Encrypt );
            ecb.update( v.as_bytes(), output);
            ecb.end(output); 
        })
    }

    fn decrypt<T : CipherCore>( &self, text : &[u8]) -> Result<String,()> {
        
        let mut v = Vec::new();
        let mut ecb = ECBMode::<T>::init(&self.key, CipherMode::Decrypt );
        ecb.update( text, &mut v);
        ecb.end(&mut v);

        let s = to_ascii(&v, false);
        from_uri(&s).and_then(|v| Some(to_json(&v)) ).ok_or(())
    }
}


fn main() {

    let mut rng = thread_rng();
    let key : Vec<u8> = Vec::from_iter((0..Aes128::BYTES).map(|_| rng.gen() ));
    let len = Aes128::BYTES;

    let oracle = CutAndPasteOracle::new::<Aes128>(key);

    let entry = "blablabla@admin00000000000";
    let mut res = Vec::new();

    oracle.encrypt::<Aes128>(entry, &mut res).expect("problem parsing");
    /*
        *10 bytes filler again

        *9 bytes filler after that
    */
    let other_entry = "blablabla@lol";

    let mut res_s = Vec::new();

    oracle.encrypt::<Aes128>( other_entry, &mut res_s).expect("problem parsing");

    let mut fake = Vec::new();
    
    res_s[0..res_s.len()-len ].clone_into(&mut fake);

    fake.extend_from_slice(&res[len..2*len]);

    let dec = oracle.decrypt::<Aes128>(&fake).expect("problem parsing");

    println!("{dec}");
}
