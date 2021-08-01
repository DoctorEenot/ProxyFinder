use std::net::UdpSocket;
use rand::Rng;
use std::mem::transmute;


pub fn look_up(hostname:String,dns_server:String) -> String{
    // Not asynchronous function!
    // Just gets ip address of domain

    let mut rng = rand::thread_rng();

    let mut port:u16 = rng.gen();
    port = 1 + (port%65535);
    let socket = UdpSocket::bind(format!("0.0.0.0:{}",port)).unwrap();

    let mut buffer:[u8;1024] = [0;1024];
    let mut data_to_send:Vec<u8> = Vec::new();

    

    // generating packet

    // transaction id
    let transaction_id:u16 = rng.gen();

    let mut bytes:[u8;8];
    bytes = unsafe{transmute(transaction_id as u64)};

    data_to_send.push(bytes[1]);
    data_to_send.push(bytes[0]);

    // flags
    data_to_send.push(0x01);
    data_to_send.push(0x00);

    // N questions
    data_to_send.push(0x00);
    data_to_send.push(0x01);

    // N answers
    data_to_send.push(0x00);
    data_to_send.push(0x00);

    // N authority RRs
    data_to_send.push(0x00);
    data_to_send.push(0x00);

    // N additional RRs
    data_to_send.push(0x00);
    data_to_send.push(0x00);

    // QUERIE

    // name
    let mut split = hostname.split(".");
    for s in split {
        data_to_send.push(s.len() as u8);
        data_to_send.extend(s.as_bytes());
    }
    data_to_send.push(0x00);

    // Type
    data_to_send.push(0x00);
    data_to_send.push(0x01);

    // Class
    data_to_send.push(0x00);
    data_to_send.push(0x01);

    // receiving packet
    socket.send_to(&data_to_send as &[u8] ,dns_server);
    let mut filled_buf:&[u8] = &[];
    while true{
        let (n_bytes, src) = socket.recv_from(&mut buffer).unwrap();
        filled_buf = &mut buffer[..n_bytes];
        // check if right transaction id
        if filled_buf[0] == bytes[1] &&
            filled_buf[1] == bytes[0]&&
            (filled_buf[2]&128) == 128{
                break;
        }
    }
    //println!("{:X?}",filled_buf);
    // parsing packet
    let error_code:u8 = filled_buf[3]&15;
    if error_code != 0{
        panic!("Error with code {} occured",error_code);
    }

    let n_questions:u16 = ((filled_buf[4] as u16)<<8)
                            |filled_buf[5] as u16;


    let n_answers:u16 = ((filled_buf[6] as u16)<<8)
                        |filled_buf[7] as u16;


    if n_questions == 0 &&
        n_answers == 0{
        panic!("wrong amount of questions or answers");
    }

    // skipping queries
    let mut buffer_index = 12;
    for i in 0..n_questions{
        // skip domain name
        while filled_buf[buffer_index] != 0
                &&filled_buf[buffer_index] != 0x13{
            buffer_index += 1;
        }
        buffer_index += 5;
    }


    // skipping non A type
    //println!("{} {}",buffer_index,filled_buf[buffer_index]);
    let mut found_ip_address:bool = false;

    for i in 0..n_answers{
        if filled_buf[buffer_index] == 0xc0
            ||(filled_buf[buffer_index]&0b11000000)==0b11000000{
            buffer_index += 2;
        }
        else{
            
            while filled_buf[buffer_index] != 0
                    &&filled_buf[buffer_index] != 0x13{
                buffer_index += 1;
            }
            buffer_index += 1;
        }

        if filled_buf[buffer_index] == 0
                &&filled_buf[buffer_index+1] == 1{
                found_ip_address = true;
            break;
        }
        else if filled_buf[buffer_index] == 0
                && filled_buf[buffer_index+1] == 5{
            buffer_index += 8;
            let mut answer_data_length = ((filled_buf[buffer_index] as u16)<<8)
                                    |filled_buf[buffer_index+1] as u16;
            buffer_index += 2;
            buffer_index += answer_data_length as usize;
            //println!("{} {}",buffer_index,filled_buf[buffer_index]);
        }

    }

    //println!("{} {}",buffer_index,filled_buf[buffer_index]);

    if !found_ip_address{
        panic!("No ip address in server's answer");
    }

    buffer_index += 8;

    // parsing 1 answer
    let data_length:u16 = ((filled_buf[buffer_index] as u16)<<8)
                            |filled_buf[buffer_index+1] as u16;
    buffer_index += 2;
    
    if data_length == 4{
        // ipv4
        let mut ip = String::new();
        
        ip.push_str(&filled_buf[buffer_index].to_string());
        ip.push('.');

        ip.push_str(&filled_buf[buffer_index+1].to_string());
        ip.push('.');

        ip.push_str(&filled_buf[buffer_index+2].to_string());
        ip.push('.');

        ip.push_str(&filled_buf[buffer_index+3].to_string());

        return ip;
    }
    else{
        panic!("Other IP versions not implemented");
    }
}

