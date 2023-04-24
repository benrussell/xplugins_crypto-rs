


fn print_hex_blob( data: &Vec<u8> ){
    
    let mut counter_newline = 0;
    let mut counter_space = 0;
    
    for b in data.iter(){
        print!("{:02x}", b);

        counter_space += 1;
        if counter_space == 4 {
            print!(" ");
            counter_space = 0;
        }

        counter_newline += 1;
        if counter_newline >= 36 {
            println!("");
            counter_newline = 0;
            counter_space = 0;
        }
        
    }

}

