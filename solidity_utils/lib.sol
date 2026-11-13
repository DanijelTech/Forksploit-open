// Author: DanyTech
pragma solidity ^0.8.0;

library ForkSploitBug {
    event AssertionFailed(string message);

    function bug() internal {
        emit AssertionFailed("Bug");
    }

    function typed_bug(string memory data) internal {
        emit AssertionFailed(data);
    }

}


function bug()  {
    ForkSploitBug.bug();
}

function typed_bug(string memory data)  {
    ForkSploitBug.typed_bug(data);
}
