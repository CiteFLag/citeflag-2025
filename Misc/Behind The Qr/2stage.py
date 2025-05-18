import numpy as np
import matplotlib.pyplot as plt
from scipy.io import wavfile
from scipy import signal
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend to prevent hanging

def extract_spectrogram(audio_file, output_file, start_time=7, end_time=17):
    """
    Extract standard spectrogram from a specific time range in an audio file
    
    Parameters:
    -----------
    audio_file : str
        Path to the audio file
    output_file : str
        Path to save the spectrogram image
    start_time : float
        Start time in seconds
    end_time : float
        End time in seconds
    """
    print(f"Processing audio file: {audio_file}")
    print(f"Extracting spectrogram from {start_time}s to {end_time}s")
    
    # Read the audio file
    try:
        sample_rate, audio_data = wavfile.read(audio_file)
        print(f"Sample rate: {sample_rate} Hz")
        print(f"Total duration: {len(audio_data)/sample_rate:.2f} seconds")
    except Exception as e:
        print(f"Error reading audio file: {e}")
        return
    
    # Convert to mono if stereo
    if len(audio_data.shape) > 1:
        print("Converting stereo to mono")
        audio_data = audio_data.mean(axis=1).astype(audio_data.dtype)
    
    # Extract the segment of interest
    start_index = int(start_time * sample_rate)
    end_index = int(end_time * sample_rate)
    
    if end_index > len(audio_data):
        print(f"Warning: Requested end time exceeds audio duration. Using available data.")
        end_index = len(audio_data)
    
    audio_segment = audio_data[start_index:end_index]
    print(f"Extracted segment duration: {len(audio_segment)/sample_rate:.2f} seconds")
    
    # Generate spectrogram with high resolution settings
    frequencies, times, spectrogram = signal.spectrogram(
        audio_segment, 
        sample_rate, 
        nperseg=2048,  # Window size 
        noverlap=1536,  # 75% overlap for better resolution
        scaling='spectrum'
    )
    
    # Convert to dB scale for better visualization
    spectrogram_db = 10 * np.log10(spectrogram + 1e-10)
    
    # Create a figure for the standard spectrogram
    plt.figure(figsize=(12, 8))
    plt.pcolormesh(times, frequencies, spectrogram_db, shading='gouraud', cmap='inferno')
    plt.title('Standard Spectrogram (7-17 seconds)')
    plt.ylabel('Frequency [Hz]')
    plt.xlabel('Time [sec]')
    plt.colorbar(label='Intensity [dB]')
    plt.tight_layout()
    plt.savefig(output_file, dpi=300)
    print(f"Spectrogram saved to: {output_file}")
    plt.close()
    
    print("Processing complete!")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Audio Spectrogram Extractor")
    parser.add_argument("audio_file", help="Path to the audio file to analyze")
    parser.add_argument("--output", "-o", default="spectrogram.png", 
                       help="Path to save the spectrogram image")
    parser.add_argument("--start", "-s", type=float, default=7.0,
                       help="Start time in seconds (default: 7.0)")
    parser.add_argument("--end", "-e", type=float, default=17.0,
                       help="End time in seconds (default: 17.0)")
    
    args = parser.parse_args()
    
    extract_spectrogram(args.audio_file, args.output, args.start, args.end)