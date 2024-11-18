import wave
import numpy as np

# Morse Code Dictionary
MORSE_CODE_DICT = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3',
    '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8',
    '----.': '9', '/': ' '
}


def decode_morse(signal_durations, threshold=0.1):
    morse_sequence = []
    for duration in signal_durations:
        if duration < threshold:  # Dot
            morse_sequence.append('.')
        elif duration < threshold * 3:  # Dash
            morse_sequence.append('-')
        else:  # Pause
            morse_sequence.append('/')
    return ''.join(morse_sequence)


def wav_to_morse(file_path, threshold=0.5):
    with wave.open(file_path, 'r') as wav_file:
        frames = wav_file.readframes(-1)
        sample_rate = wav_file.getframerate()
        audio = np.frombuffer(frames, dtype=np.int16)

    # Normalize audio
    audio = audio / np.max(np.abs(audio))

    # Detect signal envelope
    envelope = np.abs(audio) > threshold

    # Identify durations
    durations = np.diff(np.where(np.diff(envelope) != 0)[0])
    durations = durations / sample_rate

    # Decode Morse
    morse_code = decode_morse(durations)

    # Convert Morse to text
    words = ''.join(MORSE_CODE_DICT.get(code, '') for code in morse_code.split('/'))
    return words


# Update the file path to the correct location
file_path = "/home/mark/Downloads/Enigma.wav"
text = wav_to_morse(file_path)
print("Decoded Text:", text)
