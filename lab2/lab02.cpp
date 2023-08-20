#include <iostream>
#include <stdio.h>
#include <vector>
#include <string>
// #include <io.h>
#include <filesystem>
#include <fstream>
#include <sstream>

using namespace std;
namespace fs = std::filesystem;

string asciiToString(string str){
    int num = 0;
    string ans = "";

    for (int i = 0; i < str.length(); i++) {
        // Append the current digit
        num = num * 10 + (str[i] - '0');
        // If num is within the required range
        if (num >= 32 && num <= 122) {
            // Convert num to char
            char ch = (char)num;
            ans += ch;
            // Reset num to 0
            num = 0;
        }
    }
    return ans;
}

void get_files(string path, vector<string>& files){
    fs::path pth(path);
    fs::directory_entry Dir(pth);

    for (fs::recursive_directory_iterator end,begin(Dir);begin!=end;++begin){
		if (!fs::is_directory(begin->path())) 
		{
			files.push_back(fs::absolute(begin->path()).string());
            // cout << begin->path().string() << endl;
		}else{
            // if(begin->path() != )
            // get_files(begin->path(), files);
        }
	}
}

int main(int argc, char *argv[]) {
    // cout << argv[1] << " " << argv[2] << endl;
    string file_path = argv[1];
    string target = argv[2];

    vector<string> ans;

    vector<string> files;
    get_files(file_path, files);

    for(int i=0;i<files.size();i++) {
        // cerr << "file "<< files[i] << endl;
        fstream ifs(files[i], std::ios::in);
        if (!ifs.is_open()) {
            cout << "Failed to open file.\n";
            return 1;
        }
        stringstream ss;
        ss << ifs.rdbuf();
        string str(ss.str());
        // cout << "str: " << str << "\n";
        // cout << "target: "<< target << endl;
        if(str.find(target) != string::npos){
            ans.push_back(files[i]);
            cout << files[i] << "\n";
            // cout << "dasdas\n";
        }
        ifs.close();
    }
    // cout<< "\nans\n";
    // for(int i=0;i<ans.size();i++){
    //     cout << ans[i] << endl;
    // }

}