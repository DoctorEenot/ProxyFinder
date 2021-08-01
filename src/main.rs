extern crate libc;

use std::error::Error;
use mio::net::{TcpStream};
use mio::{Events, Interest, Poll, Token};
use std::net::{SocketAddr,Shutdown};
use std::env;
use std::thread;
use std::sync::{Arc,Mutex};
mod dns_lookup;
use std::io::{self, prelude::*, BufReader};
use std::fs::File;
use std::time::Duration;
use std::option;
use std::str;
use std::collections::HashMap;

//http://dreenot.pythonanywhere.com/
static VERSION:&str = "1.0.0";
static FAST_STRING:&str = "specialveryuniquestringthatcannothappentobeonanysitewhatsoeverbecauseifitsthenitsanattackaginstparser";
static FAST_HTTP_PROOF:&str = "Server: PythonAnywhere";
static FAST_DOMAIN:&str = "dreenot.pythonanywhere.com";
static FAST_HOST:&str = "dreenot.pythonanywhere.com";
static FAST_PORT:u16 = 80;
static FAST_URL:&str = "http://dreenot.pythonanywhere.com/";
static HTTPS_QUERY:&[u8;39] = b"CONNECT www.google.com:443 HTTP/1.0\r\n\r\n";
static FAST_HTTPS_PROOF:&str = "200 Connection established";


fn help(){
    println!("ProxyFinder version: {}\n",VERSION);
    println!("Usage:");
    println!("-h/--help print that message");
    println!("-t/--threads set amount of threads for processing");
    println!("-o/--output specify file(path+file) to output to");
    println!("-i/--input specify file(path+file) to get targets from");
    println!("-tm/--timeout specify timeout for connection in seconds");
    println!("-f/--fast use quick proxy determination");
    println!("-ver/--verifyiers set custom sites to detect proxy(slow)");
    println!("                  if -f/--fast is set, ignored");
}

fn fast_is_valid(response:&mut Vec<u8>)->bool{
    let mut counter:usize=0;
    let mut headers_found:bool = false;
    if response.len() == 0{
        return false;
    }
    // find and skip headers
    while counter < response.len()-3{
        if response[counter] == 13
                && response[counter+1] == 10{
            if response[counter+2] == 13
                    &&response[counter+3] == 10{
                headers_found = true;
                counter += 4;
                break;
            }
            else{
                counter += 2;
                continue
            }
        }
        counter += 1;
    }
    if !headers_found{
        let fast_string = FAST_STRING.as_bytes();
        for i in 0..response.len(){
            if response[i] != fast_string[i]{
                return false;
            }
        }
        return true;
    }

    if (response.len()-counter)<FAST_STRING.len(){
        return false;
    }

    // comparing payload with FAST_STRING
    let fast_string = FAST_STRING.as_bytes();
    for i in 0..FAST_STRING.len(){
        if response[counter+i] != fast_string[i]{
            return false;
        }
    }
    return true;
}

fn http_is_valid(response:&mut Vec<u8>)->bool{
    let response_string = match str::from_utf8(response) {
        Ok(v) => v,
        Err(e) => return false,
    };

    if response_string.find(FAST_HTTP_PROOF).is_some(){
        return true;
    }else{
        return false;
    }
}

fn https_is_valid(response:&mut Vec<u8>)->bool{
    let response_string = match str::from_utf8(response) {
        Ok(v) => v,
        Err(e) => return false,
    };

    if response_string.find(FAST_HTTPS_PROOF).is_some(){
        return true;
    }else{
        return false;
    }
}

#[derive(Debug)]
struct CheckResult{
    address:String,
    proxy_type:u8
    // proxy types:
    //      0 - http
    //      1 - https
    //      2 - http/https
    //      socks soon    
}

fn fast_check(addresses:Vec<String>,
                timeout:u64,
                outvector_mutex:&Arc<Mutex<Vec<CheckResult>>>,
                PORTS:Vec<u16>){
                
    let mut results:HashMap<String,CheckResult> = HashMap::new();
    let actual_addresses = unsafe{addresses.len()*PORTS.len()};
    let mut retries:Vec<u16> = Vec::with_capacity(actual_addresses);
    

    let mut sockets:Vec<TcpStream> = Vec::with_capacity(actual_addresses);

    let mut sockets_tokens:Vec<Token> = Vec::with_capacity(actual_addresses);
    for i in 0..actual_addresses{
        sockets_tokens.push(Token(i));
        retries.push(0);
    }

    let mut poll = Poll::new().unwrap();
    let mut events = Events::with_capacity(actual_addresses);
    
    let mut parsed_address:SocketAddr;
    for index in 0..addresses.len(){
        unsafe{
            for i in 0..PORTS.len(){
                parsed_address = format!("{}:{}",
                                            addresses[index],
                                            PORTS[i]).parse().unwrap();
                
                sockets.push(TcpStream::connect(parsed_address).unwrap());
                poll.registry()
                        .register(&mut sockets[index+i],
                                    sockets_tokens[index+i],
                                    Interest::READABLE|Interest::WRITABLE).unwrap();
            }   
        };
    }

    let mut servers_remain:usize = actual_addresses;
    let timeout_duration:Option<Duration> = Some(Duration::new(timeout,0));

    let HTTP_QUERY = format!("GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nDNT: 1\r\nConnection: keep-alive\r\n\r\n",
                                FAST_URL,FAST_HOST);
    let HTTP_QUERY_BYTES = HTTP_QUERY.as_bytes();
    
    // check http protocol
    while servers_remain>0{
        let mut buffer:Vec<u8> = Vec::with_capacity(1024);
        let res = poll.poll(&mut events,timeout_duration);
        match res{
            Err(e) => {
                servers_remain = 0;
                break;
            }
            Ok(e) => {
                
            }
        }
        if events.is_empty(){
            servers_remain = 0;
            break;
        }
        for event in events.iter(){
            let mut index:usize = usize::from(event.token());
            
            if event.is_readable(){
                let mut result = sockets[index].read_to_end(&mut buffer);
                match result{
                    _ => {}
                }
                if http_is_valid(&mut buffer)
                    ||fast_is_valid(&mut buffer){
                    let addr = sockets[index].peer_addr();
                    match addr{
                        Err(e) =>{continue;}
                        Ok(addr)=>{
                            let addr_string = addr.to_string();
                            results.insert(addr_string.clone(),
                                            CheckResult{address:addr_string.clone(),
                                                    proxy_type:0});
                        }
                    }
                }
                sockets[index].shutdown(Shutdown::Both);
                poll.registry().deregister(&mut sockets[index]);
                servers_remain -= 1;
            }

            if event.is_writable(){
                let mut result = sockets[index].write(HTTP_QUERY_BYTES);
                match result{
                    _ => {}
                }
            }         
        }
    }

    // check https protocol
    let mut sockets:Vec<TcpStream> = Vec::with_capacity(actual_addresses);

    let mut poll = Poll::new().unwrap();
    let mut events = Events::with_capacity(actual_addresses);
    
    let mut parsed_address:SocketAddr;
    for index in 0..addresses.len(){
        unsafe{
            for i in 0..PORTS.len(){
                parsed_address = format!("{}:{}",
                                            addresses[index],
                                            PORTS[i]).parse().unwrap();
                sockets.push(TcpStream::connect(parsed_address).unwrap());
                poll.registry()
                        .register(&mut sockets[index+i],
                                    sockets_tokens[index+i],
                                    Interest::READABLE|Interest::WRITABLE).unwrap();
            }   
        };
    }
    let mut servers_remain:usize = actual_addresses;
    
    let mut buffer:Vec<u8> = Vec::with_capacity(1024);
    while servers_remain>0{
        let res = poll.poll(&mut events,timeout_duration);
        match res{
            Err(e) => {
                servers_remain = 0;
                break;
            }
            Ok(e) => {
                
            }
        }
        if events.is_empty(){
            servers_remain = 0;
            break;
        }
        for event in events.iter(){
            let mut index:usize = usize::from(event.token());
            
            if event.is_readable(){
                let mut result = sockets[index].read_to_end(&mut buffer);
                match result{
                    _ => {}
                }
                if https_is_valid(&mut buffer){
                    let addr = sockets[index].peer_addr();
                    match addr{
                        Err(e) =>{
                            sockets[index].shutdown(Shutdown::Both);
                            poll.registry().deregister(&mut sockets[index]);
                            continue;}
                        Ok(addr)=>{
                            let addr_string = addr.to_string();
                            match results.get_mut(&addr_string){
                                Some(re) => {re.proxy_type = 2}
                                None => {
                                        results.insert(addr_string.clone(),
                                        CheckResult{address:addr_string.clone(),
                                        proxy_type:1});
                                        
                                    }
                            }
                        }
                    }
                }
                sockets[index].shutdown(Shutdown::Both);
                poll.registry().deregister(&mut sockets[index]);
                servers_remain -= 1;
                
            }

            if event.is_writable(){
                let mut result = sockets[index].write(HTTPS_QUERY);
                match result{
                    _ => {}
                }
            }         
        }
    }

    let mut outvector = outvector_mutex.lock().unwrap();

    for (address, result) in &results{
        outvector.push(CheckResult{address:address.to_string(),
                                    proxy_type:result.proxy_type});
    }
    drop(outvector);
}

fn main() {

    let mut amount_of_threads:u32 = 1;
    let mut output_into_file:bool = false;
    let mut input_from_file:bool = false;
    let mut output_filename:String = String::from("");
    let mut input_filename:String = String::from("");
    let mut timeout:u64 = 30;
    let mut use_fast_search:bool = false;
    let mut verifying_urls: Vec<&str> = vec![];
    let mut ip_addresses: Vec<String> = Vec::new();
    let mut resulting_vector:Vec<CheckResult> = Vec::new();
    let mut retries:u16 = 3;
    let resulting_vector_mutex = Arc::new(Mutex::new(resulting_vector));
    let mut PORTS:Vec<u16> = vec![80,8080,3128];

    let args: Vec<String> = env::args().collect();
    // parse console line parameters
    let mut argument_counter:usize = 1;

    while argument_counter<args.len(){
        match &*args[argument_counter]{
            "-h"|"--help" => {
                help();
                return;
            }
            "-t"|"--threads"=>{
                if argument_counter == args.len()-1{
                    help();
                    panic!("-t/--threads requires specified number after");
                }
                amount_of_threads = args[argument_counter+1].parse::<u32>().unwrap();
                argument_counter += 2;
            }
            "-o"|"--output"=>{
                output_into_file = true;
                if argument_counter == args.len()-1{
                    help();
                    panic!("-o/--output requires specified file or path after");
                }
                output_filename = args[argument_counter+1].clone();
                argument_counter += 2;
            }
            "-i"|"--input"=>{
                input_from_file = true;
                if argument_counter == args.len()-1{
                    help();
                    panic!("-i/--input requires specified file or path after");
                }
                input_filename = args[argument_counter+1].clone();
                argument_counter += 2;
            }
            "-tm"|"--timeout"=>{
                if argument_counter == args.len()-1{
                    help();
                    panic!("-tm/--timeout requires specified number after");
                }
                timeout = args[argument_counter+1].parse::<u64>().unwrap();
                argument_counter += 2;
            }
            "-f"|"--fast"=>{
                use_fast_search = true;
                argument_counter += 1;
            }
            "-ver"|"--verifyiers"=>{
                if argument_counter == args.len()-1{
                    help();
                    panic!("-ver/--verifyiers requires specified urls after");
                }
                let mut split = args[argument_counter+1].split("|");
                verifying_urls = split.collect();
                argument_counter += 2;
            }
            "-rt"|"--retries"=>{
                if argument_counter == args.len()-1{
                    help();
                    panic!("-rt/--retries requires specified number after");
                }
                retries = args[argument_counter+1].parse::<u16>().unwrap();
                argument_counter += 2;
            }
            _=>{
                ip_addresses.push(args[argument_counter].clone());
                argument_counter += 1;
            }
        }
    }

    if input_from_file{
        let f = File::open(input_filename).unwrap();
        let mut reader = BufReader::new(f);

        for line in reader.lines() {
            ip_addresses.push(line.unwrap());
        }       
    }

    if ip_addresses.len() == 0{
        println!("[Error] No target were specified");
        return;
    }
    println!("[Info] {} targets in total",ip_addresses.len());

    if amount_of_threads as usize>ip_addresses.len(){
        println!("[Info] Too many threads for {} addresses, amount of threads will be truncated",ip_addresses.len());
        amount_of_threads = ip_addresses.len() as u32;
    }

    if use_fast_search{
        let mut buffer:Vec<u8> = Vec::new();
        // check fast verifyier availability
        let mut res = dns_lookup::look_up(String::from(FAST_DOMAIN),
                        String::from("8.8.8.8:53"));
        res += ":80";
        //println!("{}",res);
        let CLIENT:Token = Token(0);
        let mut poll = Poll::new().unwrap();
        let mut events = Events::with_capacity(1);
        let addr:SocketAddr = res.parse().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        poll.registry()
            .register(&mut client, CLIENT, Interest::READABLE | Interest::WRITABLE).unwrap();
        let HTTP_QUERY = format!("GET {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                                        FAST_URL,FAST_HOST);
        for i in 0..2 {
            poll.poll(&mut events, None).unwrap();
            for event in events.iter() {
                if event.is_writable(){
                    client.write(HTTP_QUERY.as_bytes()).unwrap();
                }
                else if event.is_readable(){
                    let mut result = client.read_to_end(&mut buffer);
                    match result{
                        _ => {}
                    }
                    break;

                }
            }
        }
        let is_valid = fast_is_valid(&mut buffer);
        if !is_valid{
            println!("[Error] Could not get valid string: \"{}\" from server: \"{}\"",FAST_STRING,FAST_DOMAIN);
            return;
        }else{
            println!("[Info] Fast search validated");
        }
        
        // preprocessing bunches of servers
        let mut bunches:Vec<Vec<String>> = Vec::with_capacity(amount_of_threads as usize);
        let mut ips_per_thread:usize = ip_addresses.len()/(amount_of_threads as usize);
        if (amount_of_threads as usize)%ip_addresses.len() != 0{
            ips_per_thread += 1;
        }
        println!("[Info] Splitting bunches for threads");
        let mut ips_counter:usize = 0;
        for i in 0..amount_of_threads{
            let mut add_vec:Vec<String> = Vec::with_capacity(ips_per_thread);
            if ips_per_thread+ips_counter > ip_addresses.len(){
                ips_per_thread = ip_addresses.len() - ips_counter;

                for i in 0..ips_per_thread{
                    add_vec.push(ip_addresses[ips_counter+i].clone());
                }
                ips_counter += ips_per_thread;
                bunches.push(add_vec);
                break;
            }
            for i in 0..ips_per_thread{
                add_vec.push(ip_addresses[ips_counter+i].clone());
            }
            ips_counter += ips_per_thread;
            bunches.push(add_vec);
        }
        println!("[Info] {} threads will be launched",bunches.len());

        // launching threads
        let mut thread_pool = vec![];
        for i in 0..bunches.len(){
            let bunch = bunches[i].clone();
            let resulting_vector_mutex = Arc::clone(&resulting_vector_mutex);
            let PORTS_copy = PORTS.clone();
            thread_pool.push(thread::spawn(move||fast_check(bunch, 
                                                            timeout, 
                                                            &resulting_vector_mutex,
                                                            PORTS_copy)));
        }

        println!("[Info] Waiting for threads to stop");
        let mut stopped_threads = 1;
        for thread in thread_pool{
            thread.join().unwrap();
            println!("[Info] {}/{} threads stoppped",
                        stopped_threads,bunches.len());
            stopped_threads += 1;
        }
        println!("[Info] All threads stopped");
        //println!("{:?}",*resulting_vector_mutex.lock().unwrap())
    }

    let resulting_vector_out = &*resulting_vector_mutex.lock().unwrap();
    println!("[Info] {} proxies found",resulting_vector_out.len());
    if resulting_vector_out.len() == 0{
        return;
    }
    if output_into_file{
        println!("[OUT] outputting into file {}",output_filename);
        let mut output = File::create(output_filename).unwrap();
        for i in 0..resulting_vector_out.len()-1{
            write!(output,"{} ",resulting_vector_out[i].address);
            match resulting_vector_out[i].proxy_type{
                0 => {write!(output,"HTTP").unwrap()},
                1 => {write!(output,"HTTPS").unwrap()},
                2 => {write!(output,"HTTP/HTTPS").unwrap()},
                _ => {}
            }
            write!(output,"\n");
        }
        write!(output,"{} ",resulting_vector_out[resulting_vector_out.len()-1].address);
        match resulting_vector_out[resulting_vector_out.len()-1].proxy_type{
            0 => {write!(output,"HTTP").unwrap()},
            1 => {write!(output,"HTTPS").unwrap()},
            2 => {write!(output,"HTTP/HTTPS").unwrap()},
            _ => {}
        }
        write!(output,"\n");
    }else{
        for i in 0..resulting_vector_out.len(){
            print!("[OUT] {} ",resulting_vector_out[i].address);
            match resulting_vector_out[i].proxy_type{
                0 => {print!("HTTP")}
                1 => {print!("HTTPS")}
                2 => {print!("HTTP/HTTPS")}
                _ => {}
            }
            print!("\n");
        }
    }

    //println!("{:?}",*resulting_vector_mutex.lock().unwrap());
    //println!("{:?}",ip_addresses);
    // let res = dns_lookup::look_up(String::from(FAST_DOMAIN),
    //                     String::from("8.8.8.8:53"));

    // println!("{}",res);
}
