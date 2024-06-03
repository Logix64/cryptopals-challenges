use std::{
    fmt::{Display, Pointer},
    io::Cursor,
};

use bytes::{Buf, Bytes, BytesMut};
use challenge36::{
    buffering::Parse,
    crypto::{
        derive_key, derive_v, generate_password, hash_to_uint, DifferentParams, NistParams,
        SRPParam, SRPParameters,
    },
    negotiation::Negotiation,
    verification::Verification,
};
use challenge38::{keyexchange::KeyExchange, server::LIMBS, ValidationError};
use crypto_bigint::{
    modular::constant_mod::Residue, rand_core::CryptoRngCore, Encoding, NonZero, RandomMod, Uint,
};
use rand::{random, thread_rng};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, BufWriter},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener, TcpStream,
    },
    sync::{
        mpsc::{self, Receiver, Sender},
        oneshot,
    },
};
use tools::digest::Hmac;

enum Message {
    Negotiation(Negotiation),
    Exchange(KeyExchange),
    Verification(Verification),
}

impl Message {
    fn check(cursor: &mut Cursor<&[u8]>) -> Result<(), ValidationError> {
        Negotiation::check(cursor)
            .map_err(|v| ValidationError::from(v))
        .or_else( |_| {
            cursor.set_position(0);
            KeyExchange::check(cursor )
                .map_err(|v| ValidationError::from(v))
        })
        .or_else( |_| {
            cursor.set_position(0);
            Verification::check(cursor)
                .map_err(|v| ValidationError::from(v))
        })
    }

    fn parse(cursor: &mut Cursor<&[u8]>) -> Result<Self, ValidationError> {
        Negotiation::parse(cursor)
            .map_err(|v| ValidationError::from(v))
            .map(|u| Self::Negotiation(u))
        .or_else( |_| {
            cursor.set_position(0);
            KeyExchange::parse(cursor)
                .map_err(|v| ValidationError::from(v))
                .map(|u| Self::Exchange(u))
        })
        .or_else( |_| {
            cursor.set_position(0);
            Verification::parse(cursor )
                .map_err(|v| ValidationError::from(v))
                .map(|u| Self::Verification(u))
        })
    }

    async fn write(
        src: &mut (impl AsyncWrite + std::marker::Unpin),
        msg: &Self,
    ) -> Result<(), ValidationError> {
        match msg {
            Self::Exchange(v) => Ok(KeyExchange::write(src, v).await?),
            Self::Negotiation(v) => Ok(Negotiation::write(src, v).await?),
            Self::Verification(v) => Ok(Verification::write(src, v).await?),
        }
    }
}

impl Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Negotiation(v) => v.fmt(f),
            Self::Exchange(v) => v.fmt(f),
            Self::Verification(v) => v.fmt(f),
        }
    }
}

struct InternalMsg {
    msg: Message,
    label: String,
    response: oneshot::Sender<Option<Message>>,
}

impl Display for InternalMsg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{} >> {}", self.label, self.msg)
    }
}

impl InternalMsg {
    async fn get(receiver: &mut Receiver<InternalMsg>) -> Self {
        loop {
            if let Some(msg) = receiver.recv().await {
                return msg;
            }
        }
    }

    fn pipe(self) -> Result<Message, ValidationError> {
        self.response
            .send(None)
            .map_err(|_| ValidationError::SendReceiveError)?;
        Ok(self.msg)
    }

    fn mutate(self, msg: Message) -> Result<Message, ValidationError> {
        self.response
            .send(Some(msg))
            .map_err(|_| ValidationError::SendReceiveError)?;
        Ok(self.msg)
    }
}

struct CheckingInstance<const LIMBS: usize, T: SRPParameters<LIMBS>> {
    client_public_key: Residue<T, LIMBS>,
    public_key: Residue<T, LIMBS>,
    private_key: Uint<LIMBS>,
    salt: Bytes,
    u: Uint<LIMBS>,
}

impl<const LIMBS: usize, T: SRPParameters<LIMBS>> CheckingInstance<LIMBS, T>
where
    Uint<LIMBS>: Encoding,
{
    fn new(rng: &mut impl CryptoRngCore, client_public_key: &Uint<LIMBS>) -> Self {
        let private_key = Uint::<LIMBS>::random_mod(rng, &NonZero::from_uint(T::MODULUS));
        let bytes: [u8; 16] = random();
        let salt: [u8; 16] = random();
        Self {
            client_public_key: Residue::new(client_public_key),
            public_key: T::G.pow(&private_key),
            private_key,
            u: hash_to_uint(&bytes),
            salt: BytesMut::from(salt.as_ref()).freeze(),
        }
    }

    fn get_public_key(&self) -> Uint<LIMBS> {
        self.public_key.retrieve()
    }

    fn get_salt(&self) -> Bytes {
        self.salt.clone()
    }

    fn get_u(&self) -> Uint<LIMBS> {
        self.u.clone()
    }

    fn check(&self, password: String, hmac: impl AsRef<[u8]>, hmac_salt: impl AsRef<[u8]>) -> bool {
        let v = derive_v(generate_password::<T::Hashing>(password, &self.salt));

        let s = self
            .client_public_key
            .mul(&v.pow(&self.u))
            .pow(&self.private_key);
        let key = derive_key::<LIMBS, T>(&s.retrieve());

        let mut mac = Hmac::<T::Hashing>::new(key.as_ref());
        mac.update(hmac_salt.as_ref());

        mac.finalize().as_ref().iter().zip( hmac.as_ref().iter() ).all(|(u,v)| u == v)
    }
}

async fn pipe(
    mut rx: OwnedReadHalf,
    wx: OwnedWriteHalf,
    sender: Sender<InternalMsg>,
    label: String,
) -> Result<(), ValidationError> {
    let mut buf = BytesMut::with_capacity(4096);
    let mut buf_writer = BufWriter::new(wx);
    loop {
        // if we reached end of stream
        if 0 == rx.read_buf(&mut buf).await? {
            return Err(ValidationError::Protocol);
        }

        // else
        let mut cursor = Cursor::new(&buf[..]);

        // if whole frame found
        match Message::check(&mut cursor) {
            Ok(_) => {
                // println!("found frame");
                // current length of message
                let len = cursor.position() as usize;

                // reset cursor
                cursor.set_position(0);

                // send to manager
                let msg = Message::parse(&mut cursor)?;
                let (tx, rx) = oneshot::channel();

                sender
                    .send(InternalMsg {
                        msg,
                        label: label.clone(),
                        response: tx,
                    })
                    .await
                    .unwrap();

                // wait for response
                // if response is some -- send that message
                if let Some(response) = rx.await.unwrap() {
                    Message::write(&mut buf_writer, &response).await?;

                // else just copy message
                } else {
                    buf_writer.write_all(&buf[0..len]).await?;
                    buf_writer.flush().await?;
                }

                // skip over message in buffer
                buf.advance(len);
            }
            Err(e) => return if e.is_incomplete() { continue } else { Err(e) },
        }
    }
}

async fn manage(mut receiver: Receiver<InternalMsg>) -> Result<(), ValidationError> {
    match get_params(&mut receiver).await? {
        SRPParam::DifferentParams => {
            check_instance::<LIMBS, DifferentParams>(&mut receiver).await?
        }
        SRPParam::NistParams => check_instance::<LIMBS, NistParams>(&mut receiver).await?,
    };
    // otherwise just listen to the stream of data
    loop {
        let v = InternalMsg::get(&mut receiver).await;
        println!("{v}");
        v.pipe()?;
    }
}

async fn check_instance<const LIMBS: usize, T: SRPParameters<LIMBS>>(
    receiver: &mut Receiver<InternalMsg>,
) -> Result<(), ValidationError>
where
    Uint<LIMBS>: Encoding,
{
    loop {
        // S -> C accept params
        println!( "next message : {}", InternalMsg::get(receiver)
            .await
            .mutate(Message::Negotiation(Negotiation::Accept) )? );
        println!("receiving public key");

        // C -> S getUsername
        let client_public_key = get_public_key(receiver).await?;

        println!("received public key");
        let instance: CheckingInstance<LIMBS, T> =
            CheckingInstance::<LIMBS, T>::new(&mut thread_rng(), &client_public_key);

        let public_key = BytesMut::from(instance.get_public_key().to_be_bytes().as_ref()).freeze();
        let u = BytesMut::from(instance.get_u().to_be_bytes().as_ref()).freeze();

        println!("return public key");
        InternalMsg::get(receiver)
            .await
            .mutate(Message::Exchange(KeyExchange::GetPublicKey {
                salt: instance.get_salt(),
                public_key,
                u,
            }))?;

        println!("waiting for hmac salt");
        let (hmac, salt) = get_hmac_salt(receiver).await?;
        tokio::spawn(bruteforce_attack(instance, hmac, salt));
        return Ok(());
    }
}

async fn bruteforce_attack<T: SRPParameters<LIMBS>, const LIMBS: usize>(
    instance: CheckingInstance<LIMBS, T>,
    hmac: impl AsRef<[u8]>,
    salt: impl AsRef<[u8]>,
) where
    Uint<LIMBS>: Encoding,
{
    println!("running password cracker");
    // just try for all 3-digit numbers
    for i in 0..1000 {
        if instance.check(format!("{}", i), &hmac, &salt) {
            println!("found password : {}", i);
        }
    }

    println!("could not find password !! ")
}

async fn get_params(receiver: &mut Receiver<InternalMsg>) -> Result<SRPParam, ValidationError> {
    loop {
        let internal_msg = InternalMsg::get(receiver).await;
        println!("{internal_msg}");
        if let Message::Negotiation(Negotiation::AuthInit { param, .. }) = internal_msg.pipe()? {
            return Ok(param);
        }
    }
}

async fn get_public_key<const LIMBS: usize>(
    receiver: &mut Receiver<InternalMsg>,
) -> Result<Uint<LIMBS>, ValidationError> {
    loop {
        let internal_msg = InternalMsg::get(receiver).await;
        println!("{internal_msg}");
        if let Message::Exchange(KeyExchange::GetUsername { public_key, .. }) = internal_msg.pipe()?
        {
            return Ok(Uint::<LIMBS>::from_be_slice(&public_key));
        }
    }
}

async fn get_hmac_salt(
    receiver: &mut Receiver<InternalMsg>,
) -> Result<(Bytes, Bytes), ValidationError> {
    loop {
        let internal_msg = InternalMsg::get(receiver).await;
        println!("{internal_msg}");
        if let Message::Verification(Verification::HMACRequest { hmac, salt }) =
            internal_msg.pipe()?
        {
            let response = InternalMsg::get(receiver).await.pipe()?;
            println!("{response}");
            return Ok((hmac, salt))
        }
    }
}

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("127.0.0.2:6380").await.unwrap();
    loop {
        if let Ok((from_client, _)) = listener.accept().await {
            if let Ok(to_server) = TcpStream::connect("127.0.0.1:6380").await {
                let (rx_from_client, wx_from_client) = from_client.into_split();
                let (rx_to_server, wx_to_server) = to_server.into_split();

                let (tx, rx) = mpsc::channel(32);

                tokio::spawn(manage(rx));

                tokio::spawn(pipe(
                    rx_from_client,
                    wx_to_server,
                    tx.clone(),
                    "c -> s".into(),
                ));

                tokio::spawn(pipe(rx_to_server, wx_from_client, tx, "s -> c".into()));
            }
        }
    }
}
