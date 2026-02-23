#include <stdio.h>
#include <stdbool.h>

// 1. Ο Τηλεφωνικός Κατάλογος (Απλός δισδιάστατος πίνακας)
// phonebook[10][10] σημαίνει: 10 μπαλάκια, και το καθένα μπορεί να έχει μέχρι 10 φίλους.
int phonebook[10][10];

// 2. Ένας μετρητής που θυμάται ΠΟΣΟΥΣ φίλους έχει το κάθε μπαλάκι
int friend_count[10];

// 3. Τα γνωστά μας αυτοκόλλητα
bool visited[10];

// --- ΒΗΜΑ 1: Φτιάχνουμε τον Κατάλογο ---
void buildPhonebook(int edges[][2], int num_edges) {
    // Στην αρχή, κανένα μπαλάκι δεν έχει φίλους (μετρητής = 0)
    for(int i = 0; i < 10; i++) {
        friend_count[i] = 0;
        visited[i] = false; // Και κανένα δεν έχει αυτοκόλλητο
    }

    // Διαβάζουμε τα ζευγαράκια
    for(int i = 0; i < num_edges; i++) {
        int ball_A = edges[i][0];
        int ball_B = edges[i][1];
        
        // Βάζουμε τον Β στους φίλους του Α
        int pos_A = friend_count[ball_A];   // Σε ποια κενή θέση θα μπει;
        phonebook[ball_A][pos_A] = ball_B;  // Τον βάζουμε
        friend_count[ball_A]++;             // Αυξάνουμε τον μετρητή του Α κατά 1

        // Βάζουμε τον Α στους φίλους του Β (ίδια λογική)
        int pos_B = friend_count[ball_B];
        phonebook[ball_B][pos_B] = ball_A;
        friend_count[ball_B]++;
    }
}

// --- ΒΗΜΑ 2: Η Αναδρομή (Το τράβηγμα) ---
void pullBall(int current_ball) {
    // Του κολλάμε το αυτοκόλλητο και το τυπώνουμε
    visited[current_ball] = true;
    printf("Sikwsa to mpalaki: %d\n", current_ball);
    
    // Κοιτάμε ΜΟΝΟ όσους φίλους έχει (μέχρι το friend_count του)
    for(int i = 0; i < friend_count[current_ball]; i++) {
        int friend_ball = phonebook[current_ball][i];
        
        // Αν ο φίλος δεν έχει αυτοκόλλητο, τον τραβάμε!
        if (visited[friend_ball] == false) {
            pullBall(friend_ball);
        }
    }
}