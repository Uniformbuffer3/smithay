use smithay::{
    backend::{
        libinput::{LibinputInputBackend, LibinputSessionInterface},
        session::{
            auto::{AutoSession, AutoSessionNotifier},
            Session,
        },
    },
    reexports::input::Libinput,
};

use xkbcommon::xkb;

pub use smithay::backend::input::{InputBackend, InputEvent};
pub use smithay::reexports::input::event::keyboard::KeyboardEventTrait;
pub use xkb::keysyms;


/**
This structure initialize the xkb components to decode key strokes to an abstract xkb representation,
making possible to handle multiple keyboards layouts.
*/
pub struct KeyboardDecoder {
    context: xkb::Context,
    keymap: xkb::Keymap,
    state: xkb::State,
}
impl KeyboardDecoder {
    fn detect_keyboard_layout_from_env() -> Result<String, ()> {
        for (var, value) in std::env::vars() {
            if var == "XKB_DEFAULT_LAYOUT" {
                return Ok(value);
            }
        }
        Err(())
    }

    fn detect_keyboard_layout_from_file() -> Result<String, ()> {
        let regex = regex::Regex::new(r"\s*XKBLAYOUT\s*=(.+)").unwrap();

        let file_data = std::fs::read_to_string("/etc/default/keyboard").unwrap();
        for line in file_data.lines() {
            if let Some(capture) = regex.captures(line) {
                return Ok(capture.get(1).unwrap().as_str().to_string());
            };
        }
        Err(())
    }

    fn detect_keyboard_layout() -> Result<String, ()> {
        //Try to detect from env
        if let Ok(layout) = Self::detect_keyboard_layout_from_env() {
            return Ok(layout);
        }

        //Try to detect from file
        if let Ok(layout) = Self::detect_keyboard_layout_from_file() {
            return Ok(layout);
        }
        Err(())
    }

    pub fn new() -> Self {
        // Initializing the xkb context with no flags
        let context = xkb::Context::new(0);

        // Detecting keyboard layout
        let keyboard_layout = match Self::detect_keyboard_layout() {
            Ok(keyboard_layout) => {
                println!("Detected layout: {}", &keyboard_layout);
                keyboard_layout
            }
            Err(_) => String::from(""),
        };

        // Initializing the keymap using empty values ("").
        // This will make xkb detect automatically the system keymap.
        let keymap = xkb::Keymap::new_from_names(&context, "", "", &keyboard_layout, "", None, 0)
            .expect("Failed to create keymap");

        // Initializing the xkb state that will be used to decode keystrokes
        let state = xkb::State::new(&keymap);

        Self {
            context,
            keymap,
            state,
        }
    }
    /// This function will decode the key into an abstract xkb representation (Keysym).
    /// The keycode will be increased by 8 because the evdev XKB rules reflect X's
    /// broken keycode system, which starts at 8
    pub fn decode_as_keysym(&self, keycode: u32) -> &[xkb::Keysym] {
        self.state.key_get_syms(keycode + 8)
    }
    pub fn decode_as_chars(&self, keycode: u32) -> Vec<char> {
        self.state.key_get_utf8(keycode + 8).chars().collect()
    }
}

impl Default for KeyboardDecoder {
    fn default() -> Self {
        Self::new()
    }
}

fn main(){
    // Initializing the session from which inputs will be gathered. Do not drop session_notifier,
    // otherwise keyboard inputs will stop to be gathered.
    let (session, session_notifier) =
        AutoSession::new(None).expect("Failed to initialize the session");

    // Getting the seat name associated with the session. A "seat" represent
    // a group of input devices associated with at least one graphic output.
    // Generally only one seat is used, but it is possible to have multiple seats, each one representing an user.
    // For example, when a system with 2 seats gather inputs, they should be separated based on the seat that generate them,
    // since they come from different users. A compositor could implement this feature, for example, by having 2 mouse pointer on the screen
    // at the same time, each one controlled by it's seat, so it's unique user.
    let seat_name = session.seat();

    // Initializing the libinput context. It require a session from which pull the inputs.
    // It is also required to specify which seat will be assigned.
    let mut context =
        Libinput::new_from_udev::<LibinputSessionInterface<AutoSession>>(session.into());
    context.udev_assign_seat(&seat_name).unwrap();

    // LibinputInputBackend is a wrapper that provide some comodity functions of over Libinput,
    // while providing a common interface, so that it could be integrated along with other inputs backend,
    // like smithay::backend::winit::WinitInputBackend.
    let backend = LibinputInputBackend::new(context, None);


    let start = std::time::Instant::now();
    let mut running = true;
    while running {
        //Dispatching events
        backend
            .dispatch_new_events(|event, _config| match event {
                InputEvent::NewSeat(seat) => {
                    println!("Seat added: {:#?}", seat);
                }
                InputEvent::SeatChanged(seat) => {
                    println!("Seat changed: {:#?}", seat);
                }
                InputEvent::SeatRemoved(seat) => {
                    println!("Seat removed: {:#?}", seat);
                }
                InputEvent::Keyboard { seat: _, event } => {
                    //Decoding keys into chars. Not all keys can be printed in a human-like format,
                    //like the Esc key, for example. Others
                    for key in keyboard_decoder.decode_as_chars(event.key()) {
                        println!("{}", key);
                    }

                    //Decoding keys into keysym
                    for key in keyboard_decoder.decode_as_keysym(event.key()) {
                        match *key {
                            keysyms::KEY_Escape => {
                                println!("Esc pressed, early exit");
                                running = false;
                            }
                            _ => {}
                        }
                    }
                }
                InputEvent::PointerMotion { seat: _, event } => {
                    println!("{:#?}", event);
                }
                InputEvent::PointerMotionAbsolute { seat: _, event } => {
                    println!("{:#?}", event);
                }
                InputEvent::PointerButton { seat: _, event } => {
                    println!("{:#?}", event);
                }
                InputEvent::PointerAxis { seat: _, event } => {
                    println!("{:#?}", event);
                }
                InputEvent::TouchDown { seat: _, event } => {
                    println!("{:#?}", event);
                }
                InputEvent::TouchMotion { seat: _, event } => {
                    println!("{:#?}", event);
                }
                InputEvent::TouchUp { seat: _, event } => {
                    println!("{:#?}", event);
                }
                InputEvent::TouchCancel { seat: _, event } => {
                    println!("{:#?}", event);
                }
                InputEvent::TouchFrame { seat: _, event } => {
                    println!("{:#?}", event);
                }
                InputEvent::Special(event) => {
                    println!("{:#?}", event);
                }
            })
            .unwrap();

        //After 5 seconds the loop terminate and give the control back to the terminal
        if start.elapsed().as_secs() >= 10 {
            running = false;
        }
    }
}
