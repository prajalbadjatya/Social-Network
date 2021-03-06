const express = require('express');
const router  = express.Router();
const {check, validationResult} = require('express-validator');
const auth = require('../../middleware/auth')

//Bringing in the models
const Post  = require('../../models/Post');
const Profile  = require('../../models/Profile');
const User  = require('../../models/User');

//@route : POST api/posts
//@description : Create a Post
//@Access : Private
router.post('/', [auth,
    [
        check('text', 'Text is Required').not().isEmpty()
    ]
], async(req,res)=> {
    const errors = validationResult(req);
    if(!errors.isEmpty()){
        return res.status(400).json({errors : errors.array() });
    }
    
    
    try {
        
        const user = await User.findById(req.user.id).select('-password');

        const newPost = new Post({
            text : req.body.text,
            name : user.name,
            avatar : user.avatar,
            user: req.user.id
        });

        const post = await newPost.save();
        res.send(post);

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error')
    }
    
});

//@route : GET api/posts
//@description : Get all Posts
//@Access : Private
router.get('/', auth, async(req,res)=>{
    try {
        const posts = await Post.find().sort({date:-1});
        res.json(posts);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error')
    }
})


//@route : GET api/posts/:id
//@description : Get Post by Id
//@Access : Private
router.get('/:id', auth, async(req,res)=>{
    try {
        const post = await Post.findById(req.params.id);
        if(!post){
            return res.status(404).json({
                msg: 'Post not found'
            })
        }

        res.json(post);
    } catch (err) {
        console.error(err.message);
        if(err.kind === 'ObjectId'){
            return res.status(404).json({
                msg: 'Post not found'
            })
        }
        res.status(500).send('Server Error')
    }
})



//@route : DELETE api/posts/:id
//@description : DELETE Post by Id
//@Access : Private
router.delete('/:id', auth, async(req,res)=>{
    try {
        const post = await Post.findById(req.params.id);

        //If post doesn't exist
        if(!post){
            return res.status(404).json({
                msg: 'Post not found'
            })
        }

        //Check if the post to be deleted is made by the user
        if(post.user.toString() !== req.user.id){
            return res.status(401).json({
                msg: 'Not authorized'
            })
        }
        await post.remove();
        res.json({
            msg: 'Post removed'
        });

    } catch (err) {
        console.error(err.message);
        if(err.kind === 'ObjectId'){
            return res.status(404).json({
                msg: 'Post not found'
            })
        }
        res.status(500).send('Server Error')
    }
})


//@route : PUT api/posts/like/:id
//@description : Like a post
//@Access : Private
router.put('/like/:id', auth, async(req,res)=> {
    try {
        const post = await Post.findById(req.params.id);
        //Check if the post has already been liked 

        if(post.likes.filter(like => like.user.toString() == req.user.id).length > 0){
            return res.status(400).json({ msg: 'Post already Liked' });
        }
        //unshift pushes in the beginning 
        post.likes.unshift( {user : req.user.id} );
        await post.save();
        res.json(post.likes);
        
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
})



//@route : PUT api/posts/unlike/:id
//@description : Unlike a post
//@Access : Private
router.put('/unlike/:id', auth, async(req,res)=> {
    try {
        const post = await Post.findById(req.params.id);
        //Check if the post has already been liked 

        if(post.likes.filter(like => like.user.toString() == req.user.id).length ==- 0){
            return res.status(400).json({ msg: 'Post has not been liked yet' });
        }
        
        //Remove the like
        //Getting index of the like to be removed from the likes array
        const removeIndex = post.likes.map(like => like.user.toString()).indexOf(req.user.id);
        post.likes.splice(removeIndex,1);
        await post.save();
        res.json(post.likes);

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
})


//@route : POST api/posts/comment/:id
//@description : Comment on a Post
//@Access : Private
router.post('/comment/:id', [auth,
    [
        check('text', 'Text is Required').not().isEmpty()
    ]
], async(req,res)=> {
    const errors = validationResult(req);
    if(!errors.isEmpty()){
        return res.status(400).json({errors : errors.array() });
    }
    
    
    try {
        
        const user = await User.findById(req.user.id).select('-password');
        const post = await Post.findById(req.params.id);

        const newComment = {
            text : req.body.text,
            name : user.name,
            avatar: user.avatar,
            user: req.user.id
        }

        //Adding new comment to the beginning of the Comments Array
        post.comments.unshift(newComment);

        await post.save();
        res.json(post.comments);

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error')
    }
    
});

//@route : DELETE api/posts/comment/:id/:comment_id
//@description : Delete a comment on a Post
//@Access : Private
router.delete('/comment/:id/:comment_id', auth, async(req,res)=>{
    try {
        //post where the comment to be deleted exist
        const post = await Post.findById(req.params.id);

        //pulling out comment to be deleted
        const comment = post.comments.find(comment => comment.id === req.params.comment_id);

        //If comment does not exist
        if(!comment){
            return res.status(404).json( {msg:'Comment to be deleted does not exist' } );
        }

        //checking user who is deleting the comment is the one who created the comment
        if(comment.user.toString() !== req.user.id){
            return res.status(401).json({msg: 'User not authorized'});
        }

        //Get index of the comment to be removed
        const removeIndex = post.comments.map( comment => comment.user.toString()).indexOf(req.user.id);
        
        post.comments.splice(removeIndex,1);
        await post.save();
        res.json(post.comments);


    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
})


module.exports = router; 